namespace OpenCertServer.Ca.Server.Handlers;

using System.Buffers.Text;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Ca.Utils.X509;

public static class OcspHandler
{
    public static async Task Handle(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;
        byte[] requestBytes;

        if (HttpMethods.IsPost(context.Request.Method))
        {
            var config = context.RequestServices.GetRequiredService<CaConfiguration>();
            if (config.StrictOcspHttpBinding && !string.Equals(context.Request.ContentType, "application/ocsp-request", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            var buffer = new MemoryStream();
            await context.Request.Body.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
            requestBytes = buffer.ToArray();
        }
        else
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return;
        }

        var responseBytes = await ProcessRequestAsync(context, requestBytes, cancellationToken).ConfigureAwait(false);
        var response = context.Response;
        response.ContentType = "application/ocsp-response";
        await response.Body.WriteAsync(responseBytes, cancellationToken).ConfigureAwait(false);
        await response.CompleteAsync().ConfigureAwait(false);
    }

    public static async Task HandleGet(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;
        var encodedRequest = context.Request.RouteValues["requestEncoded"] as string;
        if (string.IsNullOrWhiteSpace(encodedRequest))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        byte[] requestBytes;
        try
        {
            requestBytes = Base64Url.DecodeFromChars(encodedRequest.AsSpan());
        }
        catch
        {
            var errorResponse = new OcspResponse(OcspResponseStatus.MalformedRequest);
            var w = new AsnWriter(AsnEncodingRules.DER);
            errorResponse.Encode(w);
            context.Response.ContentType = "application/ocsp-response";
            await context.Response.Body.WriteAsync(w.Encode(), cancellationToken).ConfigureAwait(false);
            await context.Response.CompleteAsync().ConfigureAwait(false);
            return;
        }

        var responseBytes = await ProcessRequestAsync(context, requestBytes, cancellationToken).ConfigureAwait(false);
        var response = context.Response;
        response.ContentType = "application/ocsp-response";
        await response.Body.WriteAsync(responseBytes, cancellationToken).ConfigureAwait(false);
        await response.CompleteAsync().ConfigureAwait(false);
    }

    private static async Task<byte[]> ProcessRequestAsync(
        HttpContext context,
        byte[] requestBytes,
        CancellationToken cancellationToken)
    {
        var validators = context.RequestServices.GetServices<IValidateOcspRequest>();
        var storeCertificates = context.RequestServices.GetRequiredService<IStoreCertificates>();
        var caProfiles = context.RequestServices.GetService<IStoreCaProfiles>();

        OcspResponse ocspResponse;
        OcspRequest request;
        try
        {
            request = new OcspRequest(new AsnReader(requestBytes, AsnEncodingRules.DER));
        }
        catch (Exception)
        {
            return EncodeResponse(new OcspResponse(OcspResponseStatus.MalformedRequest));
        }

        try
        {
            // Run registered validators; first non-null error status wins
            var validationResults = await Task.WhenAll(validators.Select(v => v.Validate(request)))
                .ConfigureAwait(false);
            var errorStatus = validationResults.FirstOrDefault(r => r.HasValue);
            if (errorStatus.HasValue)
            {
                return EncodeResponse(new OcspResponse(errorStatus.Value));
            }

            CaProfile? profile = null;
            if (caProfiles != null)
            {
                profile = await caProfiles.GetProfile(null, cancellationToken).ConfigureAwait(false);
            }

            // Extract nonce from request extensions for echo
            X509Extension? requestNonce = null;
            if (request.TbsRequest.RequestExtensions != null)
            {
                foreach (X509Extension ext in request.TbsRequest.RequestExtensions)
                {
                    if (ext.Oid?.Value == Oids.OcspNonce)
                    {
                        requestNonce = ext;
                        break;
                    }
                }
            }

            var now = DateTimeOffset.UtcNow;
            var nextUpdate = now.Add(profile?.OcspFreshnessWindow ?? TimeSpan.FromHours(1));

            var searchResults = await Task.WhenAll(
                request.TbsRequest.RequestList.Select(r =>
                    GetCertificateStatusWithCaValidation(r.CertIdentifier, storeCertificates, profile, cancellationToken)))
                .ConfigureAwait(false);

            // Build response extensions (include nonce echo if present)
            X509ExtensionCollection? responseExtensions = null;
            if (requestNonce != null)
            {
                responseExtensions = [requestNonce];
            }

            IResponderId responderId;
            byte[] signature;
            AlgorithmIdentifier signatureAlgorithm;
            X509Certificate2[] responderCerts;

            if (profile != null)
            {
                var signingCert = profile.OcspSigningCertificate ?? profile.CertificateChain[0];
                var signingKey = profile.OcspSigningKey ?? profile.PrivateKey;

                using var sha1 = SHA1.Create();
                var keyHash = sha1.ComputeHash(signingCert.GetPublicKey());
                responderId = new ResponderIdByKey(keyHash);

                var responseData = new ResponseData(
                    TypeVersion.V1,
                    responderId,
                    now,
                    searchResults.Select(r => new SingleResponse(r.Item1, (r.Item2, r.Item3), now, nextUpdate)),
                    responseExtensions);

                (signature, signatureAlgorithm) = SignResponseData(responseData, signingKey);
                responderCerts = [signingCert];
            }
            else
            {
                // Fallback: unsigned response using injected responder ID
                responderId = context.RequestServices.GetRequiredService<IResponderId>();
                var responseData = new ResponseData(
                    TypeVersion.V1,
                    responderId,
                    now,
                    searchResults.Select(r => new SingleResponse(r.Item1, (r.Item2, r.Item3), now, nextUpdate)),
                    responseExtensions);

                signature = [];
                signatureAlgorithm = new AlgorithmIdentifier(
                    Oids.EcPublicKey.InitializeOid(Oids.EcPublicKeyFriendlyName),
                    Oids.secp521r1.InitializeOid(Oids.secp521r1FriendlyName));

                ocspResponse = new OcspResponse(
                    OcspResponseStatus.Successful,
                    new OcspBasicResponse(responseData, signatureAlgorithm, signature));
                return EncodeResponse(ocspResponse);
            }

            var finalResponseData = new ResponseData(
                TypeVersion.V1,
                responderId,
                now,
                searchResults.Select(r => new SingleResponse(r.Item1, (r.Item2, r.Item3), now, nextUpdate)),
                responseExtensions);

            ocspResponse = new OcspResponse(
                OcspResponseStatus.Successful,
                new OcspBasicResponse(finalResponseData, signatureAlgorithm, signature, responderCerts));
        }
        catch (Exception)
        {
            ocspResponse = new OcspResponse(OcspResponseStatus.InternalError);
        }

        return EncodeResponse(ocspResponse);
    }

    private static async Task<(CertId, CertificateStatus, RevokedInfo?)> GetCertificateStatusWithCaValidation(
        CertId certId,
        IStoreCertificates store,
        CaProfile? profile,
        CancellationToken cancellationToken)
    {
        // If we have a CA profile, validate the CertID issuer hashes against the CA cert
        if (profile != null)
        {
            var caCert = profile.CertificateChain[0];
            using var hasher = certId.Algorithm.AlgorithmOid.Value!.GetHashAlgorithmForCertId();
            if (hasher != null)
            {
                var expectedNameHash = hasher.ComputeHash(caCert.SubjectName.RawData);
                var expectedKeyHash = hasher.ComputeHash(caCert.GetPublicKey());

                if (!expectedNameHash.AsSpan().SequenceEqual(certId.IssuerNameHash) ||
                    !expectedKeyHash.AsSpan().SequenceEqual(certId.IssuerKeyHash))
                {
                    return (certId, CertificateStatus.Unknown, null);
                }
            }
        }

        return await store.GetCertificateStatus(certId, cancellationToken).ConfigureAwait(false);
    }

    private static (byte[] Signature, AlgorithmIdentifier Algorithm) SignResponseData(
        ResponseData responseData,
        AsymmetricAlgorithm signingKey)
    {
        var dataWriter = new AsnWriter(AsnEncodingRules.DER);
        responseData.Encode(dataWriter);
        var dataToSign = dataWriter.Encode();

        return signingKey switch
        {
            RSA rsa => (
                rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                new AlgorithmIdentifier(Oids.RsaPkcs1Sha256.InitializeOid(Oids.RsaPkcs1Sha256FriendlyName))),
            ECDsa ecdsa => (
                ecdsa.SignData(dataToSign, HashAlgorithmName.SHA256),
                new AlgorithmIdentifier(Oids.ECDsaWithSha256.InitializeOid(Oids.ECDsaWithSha256FriendlyName))),
            _ => throw new InvalidOperationException("Unsupported signing key type")
        };
    }

    private static byte[] EncodeResponse(OcspResponse response)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        response.Encode(writer);
        return writer.Encode();
    }
}
