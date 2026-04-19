namespace OpenCertServer.Est.Server.Handlers;

using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Pkcs7;
using OpenCertServer.Est.Server.Response;

internal static class ServerKeyGenHandler
{
    private const string KeyProtectionHeader = "X-Est-Keygen-Protection";
    private const string KeyProtectionStatusHeader = "X-Est-Keygen-Protection-Status";
    private const string SmimeCapabilitiesHeader = "X-Est-Smime-Capabilities";
    private const string SymmetricDecryptKeyIdentifierHeader = "X-Est-Decrypt-Key-Identifier";
    private const string AsymmetricDecryptKeyIdentifierHeader = "X-Est-Asymmetric-Decrypt-Key-Identifier";

    public static Task<IResult> Handle(
        ClaimsPrincipal user,
        HttpRequest httpRequest,
        ICertificateAuthority certificateAuthority,
        Stream body,
        IManualAuthorizationStrategy manualAuthorizationStrategy,
        CancellationToken cancellationToken)
    {
        return HandleProfile("", user, httpRequest, certificateAuthority, body, manualAuthorizationStrategy,
            cancellationToken);
    }

    public static async Task<IResult> HandleProfile(
        [FromRoute] string profileName,
        ClaimsPrincipal user,
        HttpRequest httpRequest,
        ICertificateAuthority certificateAuthority,
        Stream body,
        IManualAuthorizationStrategy manualAuthorizationStrategy,
        CancellationToken cancellationToken)
    {
        EstInstruments.ServerKeyGenRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = EstInstruments.ActivitySource.StartActivity(ActivityNames.ServerKeyGen);
        activity?.AddTag(TagKeys.Profile, profileName);
        IResult result;
        try
        {
            result = await Core().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            EstInstruments.ServerKeyGenFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            EstInstruments.ServerKeyGenDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
            throw;
        }

        var statusCode = (result as IStatusCodeHttpResult)?.StatusCode ?? 200;
        if (statusCode >= 400)
        {
            EstInstruments.ServerKeyGenFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error);
        }
        else
        {
            EstInstruments.ServerKeyGenSuccesses.Add(1);
            activity?.SetStatus(ActivityStatusCode.Ok);
        }

        EstInstruments.ServerKeyGenDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
        return result;

        async Task<IResult> Core()
        {
            try
            {
                using var reader = new StreamReader(body, Encoding.UTF8);
                var requestContent = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    requestContent = requestContent.NormalizeBase64();
                }
                catch (FormatException f)
                {
                    return Results.Text(f.Message, Constants.TextPlainMimeType, Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest);
                }
                catch (InvalidOperationException o)
                {
                    return Results.Text(o.Message, Constants.TextPlainMimeType, Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest);
                }

                if (!requestContent.TryVerifyTlsUniqueValue(out var proofOfPossessionError))
                {
                    return Results.Text(proofOfPossessionError, Constants.TextPlainMimeType, Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest);
                }

                var csrDer = Convert.FromBase64String(requestContent);
                var csr = CertificateRequest.LoadSigningRequest(
                    csrDer,
                    HashAlgorithmName.SHA256,
                    options: CertificateRequestLoadOptions.SkipSignatureValidation |
                    CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                    signerSignaturePadding: RSASignaturePadding.Pss);

                if (manualAuthorizationStrategy.TryGetPendingAuthorization(
                    httpRequest,
                    user,
                    csr,
                    out var retryAfter,
                    out var pendingMessage))
                {
                    return new RetryAfterResult(retryAfter, pendingMessage);
                }

                var encryptedKeyDelivery = GetRequestedEncryptedKeyDelivery(httpRequest);
                if (encryptedKeyDelivery.ErrorResult != null)
                {
                    return encryptedKeyDelivery.ErrorResult;
                }

                var privateKey = csr.PublicKey.Oid.Value switch
                {
                    Oids.Rsa => CreateServerSideRsaRequest(csr),
                    Oids.EcPublicKey => CreateServerSideEcRequest(csr),
                    _ => throw new NotSupportedException(
                        $"Server-side key generation does not support CSR public key algorithm '{csr.PublicKey.Oid.Value}'.")
                };

                var newCert =
                    await certificateAuthority.SignCertificateRequest(privateKey.Request, profileName,
                        user.Identity as ClaimsIdentity, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (newCert is SignCertificateResponse.Success success)
                {
                    var mpr = new MultipartContent("mixed");
                    mpr.Add(encryptedKeyDelivery.UseEncryptedKeyPart
                        ? new EstMultipartBase64Content(
                            privateKey.Pkcs8.Base64Encode(),
                            Constants.PemMimeType,
                            smimeType: "server-generated-key")
                        : new EstMultipartBase64Content(privateKey.Pkcs8.Base64Encode(), Constants.Pkcs8));
                    mpr.Add(new EstMultipartBase64Content(CreateCertsOnlyResponse(success.Certificate),
                        Constants.PemMimeType));
                    return Results.Stream(
                        await mpr.ReadAsStreamAsync(cancellationToken), mpr.Headers.ContentType!.ToString());
                }

                var error = (SignCertificateResponse.Error)newCert;
                return Results.Text(
                    string.Join(Environment.NewLine, error.Errors), Constants.TextPlainMimeType,
                    Encoding.UTF8,
                    (int)HttpStatusCode.BadRequest);
            }
            catch (Exception)
            {
                return Results.Text(
                    "An error occurred while processing the request.", Constants.TextPlainMimeType, Encoding.UTF8,
                    (int)HttpStatusCode.BadRequest);
            }
        }
    }

    private static (CertificateRequest Request, byte[] Pkcs8) CreateServerSideRsaRequest(
        CertificateRequest signingRequest)
    {
        var rsa = RSA.Create();
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        return (
            new CertificateRequest(signingRequest.SubjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            pkcs8);
    }

    private static (CertificateRequest Request, byte[] Pkcs8) CreateServerSideEcRequest(
        CertificateRequest signingRequest)
    {
        var ecdsa = ECDsa.Create();
        var pkcs8 = ecdsa.ExportPkcs8PrivateKey();
        return (new CertificateRequest(signingRequest.SubjectName, ecdsa, HashAlgorithmName.SHA256), pkcs8);
    }

    private static string CreateCertsOnlyResponse(X509Certificate2 certificate)
    {
        var signedData = new SignedData(version: 1, certificates: [certificate]);
        var contentInfo = new CmsContentInfo(
            Oids.Pkcs7Signed.InitializeOid(Oids.Pkcs7SignedFriendlyName),
            signedData);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        contentInfo.Encode(writer);
        return writer.Encode().Base64Encode();
    }

    private static bool PrefersEncryptedKeyPart(HttpRequest httpRequest)
    {
        return httpRequest.GetTypedHeaders().Accept.Any(mediaType =>
            string.Equals(mediaType.MediaType.Value, Constants.MultiPartMixed, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(
                mediaType.Parameters.FirstOrDefault(parameter =>
                        parameter.Name.Equals("smime-type", StringComparison.OrdinalIgnoreCase))
                    ?.Value.ToString().Trim('"'),
                "server-generated-key",
                StringComparison.OrdinalIgnoreCase));
    }

    private static (bool UseEncryptedKeyPart, IResult? ErrorResult) GetRequestedEncryptedKeyDelivery(
        HttpRequest httpRequest)
    {
        var prefersEncryptedKeyPart = PrefersEncryptedKeyPart(httpRequest);
        var requestedProtection = httpRequest.Headers[KeyProtectionHeader].ToString();
        var useEncryptedKeyPart = prefersEncryptedKeyPart || !string.IsNullOrWhiteSpace(requestedProtection);
        if (!useEncryptedKeyPart)
        {
            return (false, null);
        }

        var smimeCapabilities = httpRequest.Headers[SmimeCapabilitiesHeader].ToString();
        if (string.IsNullOrWhiteSpace(smimeCapabilities))
        {
            return (true, Results.Text(
                        "Encrypted server-side key delivery requires the SMIMECapabilities attribute.",
                        Constants.TextPlainMimeType,
                        Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest));
        }

        var symmetricIdentifier = httpRequest.Headers[SymmetricDecryptKeyIdentifierHeader].ToString();
        var asymmetricIdentifier = httpRequest.Headers[AsymmetricDecryptKeyIdentifierHeader].ToString();
        var protection = requestedProtection.Trim().ToLowerInvariant();
        var hasSymmetricIdentifier = !string.IsNullOrWhiteSpace(symmetricIdentifier);
        var hasAsymmetricIdentifier = !string.IsNullOrWhiteSpace(asymmetricIdentifier);

        var hasRequiredIdentifier = protection switch
        {
            "symmetric" => hasSymmetricIdentifier,
            "asymmetric" => hasAsymmetricIdentifier,
            _ => hasSymmetricIdentifier || hasAsymmetricIdentifier
        };

        if (!hasRequiredIdentifier)
        {
            return (true, Results.Text(
                        "Encrypted server-side key delivery requires a DecryptKeyIdentifier or AsymmetricDecryptKeyIdentifier attribute.",
                        Constants.TextPlainMimeType,
                        Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest));
        }

        var protectionStatus = httpRequest.Headers[KeyProtectionStatusHeader].ToString();
        if (string.Equals(protectionStatus, "unavailable", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(protectionStatus, "unusable", StringComparison.OrdinalIgnoreCase))
        {
            return (true, Results.Text(
                        "The requested key-encryption material is unavailable or unusable.",
                        Constants.TextPlainMimeType,
                        Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest));
        }

        return (true, null);
    }
}
