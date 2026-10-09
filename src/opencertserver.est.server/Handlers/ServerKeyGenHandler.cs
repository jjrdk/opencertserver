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
using Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using Ca.Utils.Pkcs7;
using OpenCertServer.Ca.Utils.X509.Templates;
using Response;

internal static class ServerKeyGenHandler
{
    private const string SmimeCapabilitiesAttributeOid = "1.2.840.113549.1.9.15";
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
                    requestContent = Convert.ToBase64String(EstRequestBody.DecodeCsr(requestContent));
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

                var encryptedKeyDelivery = GetRequestedEncryptedKeyDelivery(httpRequest, csrDer);
                if (encryptedKeyDelivery.ErrorResult != null)
                {
                    return encryptedKeyDelivery.ErrorResult;
                }

                if (encryptedKeyDelivery.UseEncryptedKeyPart && csr.PublicKey.Oid.Value != Oids.Rsa)
                {
                    return Results.Text(
                        "Encrypted server-side key delivery requires an RSA CSR public key.",
                        Constants.TextPlainMimeType,
                        Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest);
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
                    var privateKeyPart = encryptedKeyDelivery.UseEncryptedKeyPart
                        ? CreateEncryptedKeyResponse(privateKey.Pkcs8, csr)
                        : privateKey.Pkcs8.Base64Encode();
                    mpr.Add(encryptedKeyDelivery.UseEncryptedKeyPart
                        ? new EstMultipartBase64Content(
                            privateKeyPart,
                            Constants.PemMimeType,
                            smimeType: "server-generated-key")
                        : new EstMultipartBase64Content(privateKeyPart, Constants.Pkcs8));
                    mpr.Add(new EstMultipartBase64Content(CreateCertsOnlyResponse(success.Certificate),
                        Constants.PemMimeType,
                        smimeType: "certs-only"));
                    return Results.Stream(
                        await mpr.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false), mpr.Headers.ContentType!.ToString());
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
        // RFC 7030 §4.4.1: the public key of the CSR is ignored, but its size is the client's statement of what it
        // wants; without one the platform default applies.
        using var requestedKey = signingRequest.PublicKey.GetRSAPublicKey();
        var rsa = requestedKey == null ? RSA.Create() : RSA.Create(requestedKey.KeySize);
        var pkcs8 = rsa.ExportPkcs8PrivateKey();
        var request = new CertificateRequest(signingRequest.SubjectName, rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        CopyRequestContent(signingRequest, request);
        return (request, pkcs8);
    }

    private static (CertificateRequest Request, byte[] Pkcs8) CreateServerSideEcRequest(
        CertificateRequest signingRequest)
    {
        using var requestedKey = signingRequest.PublicKey.GetECDsaPublicKey();
        var ecdsa = requestedKey == null
            ? ECDsa.Create()
            : ECDsa.Create(requestedKey.ExportParameters(false).Curve);
        var pkcs8 = ecdsa.ExportPkcs8PrivateKey();
        var request = new CertificateRequest(signingRequest.SubjectName, ecdsa, HashAlgorithmName.SHA256);
        CopyRequestContent(signingRequest, request);
        return (request, pkcs8);
    }

    /// <summary>
    /// RFC 7030 §4.4.1: "the server SHOULD treat the CSR as it would any enroll or re-enroll CSR; the only
    /// distinction here is that the server MUST ignore the public key values and signature in the CSR." The
    /// requested extensions and attributes therefore travel with the new key to the CA. A subject key identifier
    /// is left out: it describes the client's key, not the one generated here.
    /// </summary>
    private static void CopyRequestContent(CertificateRequest source, CertificateRequest target)
    {
        foreach (var extension in source.CertificateExtensions)
        {
            if (extension.Oid?.Value == Oids.SubjectKeyIdentifier)
            {
                continue;
            }

            target.CertificateExtensions.Add(extension);
        }

        foreach (var attribute in source.OtherRequestAttributes)
        {
            target.OtherRequestAttributes.Add(attribute);
        }
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
        HttpRequest httpRequest,
        byte[] csrDer)
    {
        var csrAttributes = ReadCsrAttributes(csrDer);
        var hasSmimeCapabilitiesAttribute = csrAttributes.Any(attribute =>
            string.Equals(attribute.Oid.Value, SmimeCapabilitiesAttributeOid, StringComparison.Ordinal));
        var requestedViaLegacyHeaders =
            !string.IsNullOrWhiteSpace(httpRequest.Headers[KeyProtectionHeader].ToString()) ||
            !string.IsNullOrWhiteSpace(httpRequest.Headers[SmimeCapabilitiesHeader].ToString()) ||
            !string.IsNullOrWhiteSpace(httpRequest.Headers[SymmetricDecryptKeyIdentifierHeader].ToString()) ||
            !string.IsNullOrWhiteSpace(httpRequest.Headers[AsymmetricDecryptKeyIdentifierHeader].ToString());
        var prefersEncryptedKeyPart = PrefersEncryptedKeyPart(httpRequest);

        var useEncryptedKeyPart = hasSmimeCapabilitiesAttribute || requestedViaLegacyHeaders || prefersEncryptedKeyPart;
        if (!useEncryptedKeyPart)
        {
            return (false, null);
        }

        var smimeCapabilities = httpRequest.Headers[SmimeCapabilitiesHeader].ToString();
        if (!hasSmimeCapabilitiesAttribute && string.IsNullOrWhiteSpace(smimeCapabilities))
        {
            return (true, Results.Text(
                        "Encrypted server-side key delivery requires the SMIMECapabilities attribute.",
                        Constants.TextPlainMimeType,
                        Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest));
        }

        var symmetricIdentifier = httpRequest.Headers[SymmetricDecryptKeyIdentifierHeader].ToString();
        var asymmetricIdentifier = httpRequest.Headers[AsymmetricDecryptKeyIdentifierHeader].ToString();
        var requestedProtection = httpRequest.Headers[KeyProtectionHeader].ToString();
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

        if (string.Equals(protection, "symmetric", StringComparison.Ordinal))
        {
            return (true, Results.Text(
                        "Symmetric encrypted server-side key delivery is not supported.",
                        Constants.TextPlainMimeType,
                        Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest));
        }

        return (true, null);
    }

    private static IReadOnlyList<CsrAttribute> ReadCsrAttributes(byte[] csrDer)
    {
        var reader = new AsnReader(
            csrDer,
            AsnEncodingRules.DER,
            new AsnReaderOptions { SkipSetSortOrderVerification = true });
        var certificationRequestReader = reader.ReadSequence();
        var certificationRequestInfoReader = certificationRequestReader.ReadSequence();
        _ = certificationRequestInfoReader.ReadInteger();
        _ = certificationRequestInfoReader.ReadEncodedValue(); // subject
        _ = certificationRequestInfoReader.ReadEncodedValue(); // subjectPublicKeyInfo

        if (!certificationRequestInfoReader.HasData ||
            !certificationRequestInfoReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            return [];
        }

        var attributesReader =
            certificationRequestInfoReader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));
        List<CsrAttribute> attributes = [];
        while (attributesReader.HasData)
        {
            attributes.Add(new CsrAttribute(attributesReader));
        }

        return attributes;
    }

    private static string CreateEncryptedKeyResponse(byte[] privateKeyPkcs8, CertificateRequest csr)
    {
        using var recipientRsa = RSA.Create();
        recipientRsa.ImportSubjectPublicKeyInfo(csr.PublicKey.ExportSubjectPublicKeyInfo(), out _);

        var contentEncryptionKey = RandomNumberGenerator.GetBytes(32);
        var iv = RandomNumberGenerator.GetBytes(16);
        var encryptedPrivateKey = EncryptAes256Cbc(privateKeyPkcs8, contentEncryptionKey, iv);
        var encryptedContentKey = recipientRsa.Encrypt(contentEncryptionKey, RSAEncryptionPadding.Pkcs1);

        var ivWriter = new AsnWriter(AsnEncodingRules.DER);
        ivWriter.WriteOctetString(iv);

        var recipientInfo = new RecipientInfo(new KeyTransRecipientInfo(
            version: 2,
            rid: new RecipientIdentifier(ComputeSubjectKeyIdentifier(csr.PublicKey.ExportSubjectPublicKeyInfo())),
            keyEncryptionAlgorithm: new CmsAlgorithmIdentifier(
                Oids.Rsa.InitializeOid(Oids.RsaFriendlyName),
                encodedParameters: new byte[] { 0x05, 0x00 }),
            encryptedKey: encryptedContentKey));

        var envelopedData = new EnvelopedData(
            version: 2,
            recipientInfos: [recipientInfo],
            encryptedContentInfo: new EncryptedContentInfo(
                contentType: Oids.Pkcs7Data.InitializeOid(Oids.Pkcs7DataFriendlyName),
                contentEncryptionAlgorithm: new CmsAlgorithmIdentifier(
                    Oids.Aes256Cbc.InitializeOid(Oids.Aes256CbcFriendlyName),
                    ivWriter.Encode()),
                encryptedContent: encryptedPrivateKey));

        var contentInfo = new CmsContentInfo(
            Oids.Pkcs7Enveloped.InitializeOid(Oids.Pkcs7EnvelopedFriendlyName),
            envelopedData);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        contentInfo.Encode(writer);
        return writer.Encode().Base64Encode();
    }

    private static byte[] EncryptAes256Cbc(byte[] plaintext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }

    private static byte[] ComputeSubjectKeyIdentifier(byte[] spki)
    {
        var spkiReader = new AsnReader(spki, AsnEncodingRules.DER);
        var spkiSequence = spkiReader.ReadSequence();
        _ = spkiSequence.ReadSequence();
        var publicKeyBits = spkiSequence.ReadBitString(out _);
        return SHA1.HashData(publicKeyBits);
    }
}
