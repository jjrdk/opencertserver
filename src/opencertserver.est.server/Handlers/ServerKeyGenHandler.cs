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
using Microsoft.Extensions.DependencyInjection;
using Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using Ca.Utils.Pkcs7;
using OpenCertServer.Ca.Utils.X509.Templates;
using Response;

internal static class ServerKeyGenHandler
{
    private const string SmimeCapabilitiesAttributeOid = "1.2.840.113549.1.9.15";
    // RFC 7030 §4.4.1.2: id-aa-asymmDecryptKeyID, an OCTET STRING.
    private const string AsymmetricDecryptKeyIdentifierAttributeOid = "1.2.840.113549.1.9.16.2.54";
    // RFC 4108 §2.2.5, referenced by RFC 7030 §4.4.1.1: id-aa-decryptKeyID, an OCTET STRING.
    private const string DecryptKeyIdentifierAttributeOid = "1.2.840.113549.1.9.16.2.37";
    // RFC 5958 §1: id-ct-KP-aKeyPackage.
    private const string AsymmetricKeyPackageOid = "2.16.840.1.101.2.1.2.78.5";
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

                var encryptedKeyDelivery = GetRequestedEncryptedKeyDelivery(httpRequest, csrDer, csr);
                if (encryptedKeyDelivery.ErrorResult != null)
                {
                    return encryptedKeyDelivery.ErrorResult;
                }

                // Key transport (RSA) is the only supported key-encryption mechanism.
                // The recipient key is the one identified by AsymmetricDecryptKeyIdentifier
                // (validated as the CSR's own public key in GetRequestedEncryptedKeyDelivery);
                // it must therefore be RSA.
                if (encryptedKeyDelivery.UseEncryptedKeyPart && csr.PublicKey.Oid.Value != Oids.Rsa)
                {
                    return Results.Text(
                        "The identified recipient key is not an RSA key; only RSA key transport is supported.",
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
                    string privateKeyPart;
                    if (encryptedKeyDelivery.UseEncryptedKeyPart)
                    {
                        // RFC 7030 §4.4.2: the key generator signs the key before it is enveloped. The key is
                        // generated here and certified by the CA profile, so that profile's key signs it.
                        var caProfiles = httpRequest.HttpContext.RequestServices.GetService<IStoreCaProfiles>();
                        if (caProfiles == null)
                        {
                            return Results.Text(
                                "Encrypted server-side key delivery requires access to the CA profile's signing key.",
                                Constants.TextPlainMimeType,
                                Encoding.UTF8,
                                (int)HttpStatusCode.BadRequest);
                        }

                        var signer = await caProfiles.GetProfile(
                            string.IsNullOrEmpty(profileName) ? null : profileName,
                            cancellationToken).ConfigureAwait(false);
                        privateKeyPart = CreateEncryptedKeyResponse(
                            CreateSignedKeyPackage(privateKey.Pkcs8, signer),
                            csr,
                            encryptedKeyDelivery.ContentEncryptionAlgorithmOid!);
                    }
                    else
                    {
                        privateKeyPart = privateKey.Pkcs8.Base64Encode();
                    }

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

    private static (bool UseEncryptedKeyPart, IResult? ErrorResult, string? ContentEncryptionAlgorithmOid)
        GetRequestedEncryptedKeyDelivery(
            HttpRequest httpRequest,
            byte[] csrDer,
            CertificateRequest csr)
    {
        var csrAttributes = ReadCsrAttributes(csrDer);
        var hasSmimeCapabilitiesAttribute = csrAttributes.Any(attribute =>
            string.Equals(attribute.Oid.Value, SmimeCapabilitiesAttributeOid, StringComparison.Ordinal));
        // RFC 7030 §4.4.1: the key to encrypt with is named by an attribute in the CSR. The X-Est-* headers remain
        // as a fallback for clients that send them.
        var asymmetricIdentifierAttribute =
            ReadOctetStringAttribute(csrAttributes, AsymmetricDecryptKeyIdentifierAttributeOid);
        var symmetricIdentifierAttribute = ReadOctetStringAttribute(csrAttributes, DecryptKeyIdentifierAttributeOid);
        var requestedViaLegacyHeaders =
            !string.IsNullOrWhiteSpace(httpRequest.Headers[KeyProtectionHeader].ToString()) ||
            !string.IsNullOrWhiteSpace(httpRequest.Headers[SmimeCapabilitiesHeader].ToString()) ||
            !string.IsNullOrWhiteSpace(httpRequest.Headers[SymmetricDecryptKeyIdentifierHeader].ToString()) ||
            !string.IsNullOrWhiteSpace(httpRequest.Headers[AsymmetricDecryptKeyIdentifierHeader].ToString());
        var prefersEncryptedKeyPart = PrefersEncryptedKeyPart(httpRequest);

        var useEncryptedKeyPart = hasSmimeCapabilitiesAttribute ||
            asymmetricIdentifierAttribute != null ||
            symmetricIdentifierAttribute != null ||
            requestedViaLegacyHeaders ||
            prefersEncryptedKeyPart;
        if (!useEncryptedKeyPart)
        {
            return (false, null, null);
        }

        var smimeCapabilitiesHeader = httpRequest.Headers[SmimeCapabilitiesHeader].ToString();
        if (!hasSmimeCapabilitiesAttribute && string.IsNullOrWhiteSpace(smimeCapabilitiesHeader))
        {
            return (true, Results.Text(
                        "Encrypted server-side key delivery requires the SMIMECapabilities attribute.",
                        Constants.TextPlainMimeType,
                        Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest), null);
        }

        var symmetricIdentifier = httpRequest.Headers[SymmetricDecryptKeyIdentifierHeader].ToString();
        var asymmetricIdentifier = httpRequest.Headers[AsymmetricDecryptKeyIdentifierHeader].ToString();
        var requestedProtection = httpRequest.Headers[KeyProtectionHeader].ToString();
        var protection = requestedProtection.Trim().ToLowerInvariant();
        var hasSymmetricIdentifier =
            symmetricIdentifierAttribute != null || !string.IsNullOrWhiteSpace(symmetricIdentifier);
        var hasAsymmetricIdentifier =
            asymmetricIdentifierAttribute != null || !string.IsNullOrWhiteSpace(asymmetricIdentifier);

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
                        (int)HttpStatusCode.BadRequest), null);
        }

        var protectionStatus = httpRequest.Headers[KeyProtectionStatusHeader].ToString();
        if (string.Equals(protectionStatus, "unavailable", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(protectionStatus, "unusable", StringComparison.OrdinalIgnoreCase))
        {
            return (true, Results.Text(
                        "The requested key-encryption material is unavailable or unusable.",
                        Constants.TextPlainMimeType,
                        Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest), null);
        }

        // A DecryptKeyIdentifier without an AsymmetricDecryptKeyIdentifier asks for symmetric protection (§4.4.1.1),
        // even without the protection header; encrypting to the CSR key instead would hand the client an envelope
        // it did not ask for.
        var symmetricRequested = string.Equals(protection, "symmetric", StringComparison.Ordinal) ||
            (!string.Equals(protection, "asymmetric", StringComparison.Ordinal) &&
                hasSymmetricIdentifier &&
                !hasAsymmetricIdentifier);
        if (symmetricRequested)
        {
            return (true, Results.Text(
                        "Symmetric encrypted server-side key delivery is not supported.",
                        Constants.TextPlainMimeType,
                        Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest), null);
        }

        // RFC 7030 §4.4.1.2: when AsymmetricDecryptKeyIdentifier is present, the server MUST
        // match it against a held key and MUST terminate the request if no match is found.
        // This server holds the recipient key identified by the CSR's own SubjectKeyIdentifier.
        if (hasAsymmetricIdentifier)
        {
            var csrSki = ComputeSubjectKeyIdentifier(csr.PublicKey.ExportSubjectPublicKeyInfo());
            var matches = asymmetricIdentifierAttribute != null
                ? asymmetricIdentifierAttribute.AsSpan().SequenceEqual(csrSki)
                : string.Equals(asymmetricIdentifier, Convert.ToHexString(csrSki), StringComparison.OrdinalIgnoreCase) ||
                string.Equals(asymmetricIdentifier, Convert.ToBase64String(csrSki), StringComparison.Ordinal);
            if (!matches)
            {
                return (true, Results.Text(
                            "The server does not hold a key matching the specified AsymmetricDecryptKeyIdentifier.",
                            Constants.TextPlainMimeType,
                            Encoding.UTF8,
                            (int)HttpStatusCode.BadRequest), null);
            }
        }

        // RFC 7030 §4.4.1: pick the first content-encryption algorithm from the client's
        // SMIMECapabilities that this server supports.
        var selectedAlgorithm = SelectContentEncryptionAlgorithm(csrAttributes, smimeCapabilitiesHeader);
        if (selectedAlgorithm == null)
        {
            return (true, Results.Text(
                        "None of the algorithms listed in the SMIMECapabilities attribute are supported.",
                        Constants.TextPlainMimeType,
                        Encoding.UTF8,
                        (int)HttpStatusCode.BadRequest), null);
        }

        return (true, null, selectedAlgorithm);
    }

    private static string? SelectContentEncryptionAlgorithm(
        IReadOnlyList<CsrAttribute> csrAttributes,
        string smimeCapabilitiesHeader)
    {
        // Server-supported content-encryption OIDs in preference order.
        var serverSupported = new[] { Oids.Aes256Cbc, Oids.Aes128Cbc };

        var clientOids = new List<string>();

        // Parse OIDs from the CSR's SMIMECapabilities attribute (OID 1.2.840.113549.1.9.15).
        // The attribute value is a DER SEQUENCE OF SMIMECapability where each SMIMECapability
        // is a SEQUENCE { capabilityID OBJECT IDENTIFIER, parameters ANY OPTIONAL }.
        var smimeAttr = csrAttributes.FirstOrDefault(attribute =>
            string.Equals(attribute.Oid.Value, SmimeCapabilitiesAttributeOid, StringComparison.Ordinal));
        if (smimeAttr != null)
        {
            foreach (var value in smimeAttr.Values)
            {
                try
                {
                    var capReader = new AsnReader(value, AsnEncodingRules.DER,
                        new AsnReaderOptions { SkipSetSortOrderVerification = true });
                    var capsSeq = capReader.ReadSequence();
                    while (capsSeq.HasData)
                    {
                        var capSeq = capsSeq.ReadSequence();
                        clientOids.Add(capSeq.ReadObjectIdentifier());
                    }
                }
                catch (AsnContentException)
                {
                    // Skip malformed capability values.
                }
            }
        }

        // Parse OIDs (or friendly names) from the X-Est-Smime-Capabilities header.
        if (!string.IsNullOrWhiteSpace(smimeCapabilitiesHeader))
        {
            foreach (var token in smimeCapabilitiesHeader.Split([',', ';', ' '],
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var oid = MapSmimeCapabilityNameToOid(token);
                if (oid != null)
                {
                    clientOids.Add(oid);
                }
            }
        }

        // Return the first client-listed OID that the server supports (client order takes priority).
        foreach (var oid in clientOids)
        {
            if (Array.IndexOf(serverSupported, oid) >= 0)
            {
                return oid;
            }
        }

        return null;
    }

    private static string? MapSmimeCapabilityNameToOid(string name)
    {
        return name.ToLowerInvariant() switch
        {
            "aes256-cbc" or "aes-256-cbc" or "aes256" => Oids.Aes256Cbc,
            "aes128-cbc" or "aes-128-cbc" or "aes128" => Oids.Aes128Cbc,
            // Treat unrecognised tokens as OID strings directly.
            _ => name
        };
    }

    private static byte[]? ReadOctetStringAttribute(IReadOnlyList<CsrAttribute> csrAttributes, string oid)
    {
        var value = csrAttributes
            .FirstOrDefault(attribute => string.Equals(attribute.Oid.Value, oid, StringComparison.Ordinal))?
            .Values.FirstOrDefault();
        if (value == null)
        {
            return null;
        }

        try
        {
            return new AsnReader(value, AsnEncodingRules.DER).ReadOctetString();
        }
        catch (AsnContentException)
        {
            return null;
        }
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

    /// <summary>
    /// RFC 7030 §4.4.2: "the private key is placed inside of a CMS SignedData. The SignedData is signed by the party
    /// that generated the private key". The key travels as an AsymmetricKeyPackage (RFC 5958 §2) holding the
    /// PKCS#8 PrivateKeyInfo, which is OneAsymmetricKey version 1. The signer is identified by issuer and serial
    /// number, and its certificate is included so the client can verify against /cacerts.
    /// </summary>
    /// <returns>The DER encoding of the SignedData content.</returns>
    private static byte[] CreateSignedKeyPackage(byte[] privateKeyPkcs8, CaProfile signer)
    {
        var signerCertificate = signer.CertificateChain[0];
        var (signatureAlgorithmOid, writeNullParameters) = signer.PrivateKey switch
        {
            RSA => (Oids.RsaPkcs1Sha256, true),
            ECDsa => (Oids.ECDsaWithSha256, false),
            _ => throw new NotSupportedException(
                $"Signing the server-generated key with a '{signer.PrivateKey.GetType().Name}' key is not supported.")
        };

        var keyPackageWriter = new AsnWriter(AsnEncodingRules.DER);
        using (keyPackageWriter.PushSequence())
        {
            keyPackageWriter.WriteEncodedValue(privateKeyPkcs8);
        }

        var keyPackage = keyPackageWriter.Encode();

        // RFC 5652 §5.4: the signature covers the DER encoding of the signed attributes with an explicit SET OF tag.
        var signedAttributes = WriteSignedAttributes(null, keyPackage);
        var signature = signer.PrivateKey switch
        {
            RSA rsa => rsa.SignData(signedAttributes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => ecdsa.SignData(signedAttributes, HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence),
            _ => throw new UnreachableException()
        };

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            // RFC 5652 §5.1: version 3, because the encapsulated content type is not id-data.
            writer.WriteInteger(3);
            using (writer.PushSetOf())
            {
                WriteAlgorithmIdentifier(writer, Oids.Sha256, false);
            }

            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(AsymmetricKeyPackageOid);
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    writer.WriteOctetString(keyPackage);
                }
            }

            using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            {
                writer.WriteEncodedValue(signerCertificate.RawData);
            }

            using (writer.PushSetOf())
            {
                using (writer.PushSequence())
                {
                    // RFC 5652 §5.3: version 1 with an issuerAndSerialNumber signer identifier.
                    writer.WriteInteger(1);
                    using (writer.PushSequence())
                    {
                        writer.WriteEncodedValue(signerCertificate.IssuerName.RawData);
                        writer.WriteInteger(signerCertificate.SerialNumberBytes.Span);
                    }

                    WriteAlgorithmIdentifier(writer, Oids.Sha256, false);
                    writer.WriteEncodedValue(
                        WriteSignedAttributes(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true), keyPackage));
                    WriteAlgorithmIdentifier(writer, signatureAlgorithmOid, writeNullParameters);
                    writer.WriteOctetString(signature);
                }
            }
        }

        return writer.Encode();
    }

    private static byte[] WriteSignedAttributes(Asn1Tag? tag, byte[] content)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSetOf(tag))
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Oids.ContentType);
                using (writer.PushSetOf())
                {
                    writer.WriteObjectIdentifier(AsymmetricKeyPackageOid);
                }
            }

            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Oids.MessageDigest);
                using (writer.PushSetOf())
                {
                    writer.WriteOctetString(SHA256.HashData(content));
                }
            }
        }

        return writer.Encode();
    }

    private static void WriteAlgorithmIdentifier(AsnWriter writer, string oid, bool nullParameters)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            if (nullParameters)
            {
                writer.WriteNull();
            }
        }
    }

    /// <summary>
    /// Wraps the signed key package in a CMS EnvelopedData structure (RFC 5652) using:
    /// <list type="bullet">
    ///   <item>id-RSAES-OAEP with SHA-256 for key transport (RFC 8017 §7.1 recommendation)</item>
    ///   <item>the content-encryption algorithm selected from the client's SMIMECapabilities</item>
    /// </list>
    /// The recipient is identified by the CSR public key's SubjectKeyIdentifier.
    /// </summary>
    private static string CreateEncryptedKeyResponse(
        byte[] signedKeyPackage,
        CertificateRequest csr,
        string contentEncryptionAlgorithmOid)
    {
        using var recipientRsa = RSA.Create();
        recipientRsa.ImportSubjectPublicKeyInfo(csr.PublicKey.ExportSubjectPublicKeyInfo(), out _);

        var (keySize, algorithmOid, algorithmFriendlyName) = contentEncryptionAlgorithmOid switch
        {
            Oids.Aes128Cbc => (16, Oids.Aes128Cbc, Oids.Aes128CbcFriendlyName),
            _ => (32, Oids.Aes256Cbc, Oids.Aes256CbcFriendlyName)
        };

        var contentEncryptionKey = RandomNumberGenerator.GetBytes(keySize);
        var iv = RandomNumberGenerator.GetBytes(16);
        var encryptedPrivateKey = EncryptAesCbc(signedKeyPackage, contentEncryptionKey, iv);
        // RFC 8017 §7.1: use RSAES-OAEP (SHA-256) in preference to RSAES-PKCS1-v1_5 for new applications.
        var encryptedContentKey = recipientRsa.Encrypt(contentEncryptionKey, RSAEncryptionPadding.OaepSHA256);

        var ivWriter = new AsnWriter(AsnEncodingRules.DER);
        ivWriter.WriteOctetString(iv);

        var recipientInfo = new RecipientInfo(new KeyTransRecipientInfo(
            version: 2,
            rid: new RecipientIdentifier(ComputeSubjectKeyIdentifier(csr.PublicKey.ExportSubjectPublicKeyInfo())),
            keyEncryptionAlgorithm: new CmsAlgorithmIdentifier(
                Oids.RsaOaep.InitializeOid(Oids.RsaOaepFriendlyName),
                encodedParameters: BuildOaepSha256Parameters()),
            encryptedKey: encryptedContentKey));

        var envelopedData = new EnvelopedData(
            version: 2,
            recipientInfos: [recipientInfo],
            encryptedContentInfo: new EncryptedContentInfo(
                contentType: Oids.Pkcs7Signed.InitializeOid(Oids.Pkcs7SignedFriendlyName),
                contentEncryptionAlgorithm: new CmsAlgorithmIdentifier(
                    algorithmOid.InitializeOid(algorithmFriendlyName),
                    ivWriter.Encode()),
                encryptedContent: encryptedPrivateKey));

        var contentInfo = new CmsContentInfo(
            Oids.Pkcs7Enveloped.InitializeOid(Oids.Pkcs7EnvelopedFriendlyName),
            envelopedData);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        contentInfo.Encode(writer);
        return writer.Encode().Base64Encode();
    }

    /// <summary>
    /// Builds the RSAES-OAEP-params DER value for SHA-256 hash and MGF1-SHA256 mask generation.
    /// </summary>
    private static byte[] BuildOaepSha256Parameters()
    {
        // RSAES-OAEP-params ::= SEQUENCE {
        //   hashAlgorithm      [0] HashAlgorithm    -- sha256
        //   maskGenAlgorithm   [1] MaskGenAlgorithm -- mgf1 with sha256
        // }
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(Oids.Sha256);
                    writer.WriteNull();
                }
            }

            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(Oids.Mgf1);
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(Oids.Sha256);
                        writer.WriteNull();
                    }
                }
            }
        }

        return writer.Encode();
    }

    private static byte[] EncryptAesCbc(byte[] plaintext, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.KeySize = key.Length * 8;
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
