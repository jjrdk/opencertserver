namespace OpenCertServer.Scep.Server;

using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Pkcs7;
using CmsContentInfoPkcs = System.Security.Cryptography.Pkcs.ContentInfo;

/// <summary>
/// A decoded SCEP <c>pkiMessage</c> (RFC 8894, section 3.2).
/// </summary>
/// <param name="MessageType">The message type.</param>
/// <param name="TransactionId">The transaction ID chosen by the client.</param>
/// <param name="SenderNonce">The client's nonce; echoed as <c>recipientNonce</c>.</param>
/// <param name="SignerCertificate">The certificate the client signed with - self-signed for an
/// initial enrollment, the existing certificate for a renewal. The response is encrypted to it.</param>
/// <param name="CsrDer">The decrypted PKCS#10 request, if the message carried one.</param>
public sealed record ScepRequest(
    ScepMessageType MessageType,
    string TransactionId,
    byte[] SenderNonce,
    X509Certificate2 SignerCertificate,
    byte[]? CsrDer);

/// <summary>
/// Raised when a SCEP message cannot be processed; carries the <c>failInfo</c> to answer with.
/// </summary>
public sealed class ScepException(ScepFailInfo failInfo, string message, Exception? inner = null)
    : Exception(message, inner)
{
    /// <summary>The failInfo for the CertRep.</summary>
    public ScepFailInfo FailInfo { get; } = failInfo;
}

/// <summary>
/// Reads SCEP requests and writes SCEP responses.
/// </summary>
/// <remarks>
/// Signing and enveloping use <see cref="SignedCms"/> and <see cref="EnvelopedCms"/> from
/// System.Security.Cryptography.Pkcs; the degenerate certificates-only structures reuse the
/// project's own <see cref="SignedData"/>, as the EST server does.
/// Message layout follows RFC 8894; the attribute handling is modelled on
/// smallstep/scep (MIT), originally micromdm/scep.
/// </remarks>
public static class ScepMessageCodec
{
    /// <summary>
    /// Decodes and verifies a <c>pkiMessage</c> and decrypts its envelope with the RA key.
    /// </summary>
    public static ScepRequest Decode(byte[] pkiMessage, X509Certificate2 raCertificate)
    {
        var signed = new SignedCms();
        try
        {
            signed.Decode(pkiMessage);
            // Only the signature: for an initial enrollment the signer certificate is
            // self-signed by design, so a chain check would always fail.
            signed.CheckSignature(verifySignatureOnly: true);
        }
        catch (CryptographicException ex)
        {
            throw new ScepException(ScepFailInfo.BadMessageCheck, "The message signature could not be verified.", ex);
        }

        if (signed.SignerInfos.Count != 1)
        {
            throw new ScepException(ScepFailInfo.BadMessageCheck, "A SCEP message must have exactly one signer.");
        }

        var signer = signed.SignerInfos[0];
        var signerCertificate = signer.Certificate
            ?? throw new ScepException(ScepFailInfo.BadMessageCheck, "The signer certificate is missing.");

        string? messageType = null;
        string? transactionId = null;
        byte[]? senderNonce = null;
        foreach (var attribute in signer.SignedAttributes)
        {
            if (attribute.Values.Count == 0)
            {
                continue;
            }

            var raw = attribute.Values[0].RawData;
            switch (attribute.Oid.Value)
            {
                case ScepOids.MessageType:
                    messageType = ReadString(raw);
                    break;
                case ScepOids.TransactionId:
                    transactionId = ReadString(raw);
                    break;
                case ScepOids.SenderNonce:
                    senderNonce = new AsnReader(raw, AsnEncodingRules.BER).ReadOctetString();
                    break;
            }
        }

        if (messageType is null || transactionId is null || senderNonce is null)
        {
            throw new ScepException(ScepFailInfo.BadRequest,
                "messageType, transactionID and senderNonce are required.");
        }

        if (!int.TryParse(messageType, NumberStyles.None, CultureInfo.InvariantCulture, out var typeNumber)
            || !Enum.IsDefined(typeof(ScepMessageType), typeNumber))
        {
            throw new ScepException(ScepFailInfo.BadRequest, $"Unknown messageType '{messageType}'.");
        }

        byte[]? csr = null;
        var content = signed.ContentInfo.Content;
        if (content.Length > 0)
        {
            try
            {
                var enveloped = new EnvelopedCms();
                enveloped.Decode(content);
                enveloped.Decrypt(new X509Certificate2Collection(raCertificate));
                csr = enveloped.ContentInfo.Content;
            }
            catch (CryptographicException ex)
            {
                throw new ScepException(ScepFailInfo.BadMessageCheck,
                    "The envelope could not be decrypted with the RA key.", ex);
            }
        }

        return new ScepRequest((ScepMessageType)typeNumber, transactionId, senderNonce, signerCertificate, csr);
    }

    /// <summary>
    /// Builds a successful <c>CertRep</c>: the issued certificate in a degenerate
    /// certificates-only structure, encrypted to the requester and signed by the RA.
    /// </summary>
    public static byte[] EncodeSuccess(ScepRequest request, X509Certificate2 issued, X509Certificate2 raCertificate)
    {
        var certsOnly = EncodeCertificatesOnly([issued]);
        var enveloped = new EnvelopedCms(
            new CmsContentInfoPkcs(certsOnly),
            new AlgorithmIdentifier(new Oid(Oids.Aes256Cbc)));
        enveloped.Encrypt(new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, request.SignerCertificate));
        return Sign(enveloped.Encode(), request, "0", null, raCertificate);
    }

    /// <summary>
    /// Builds a failed <c>CertRep</c> with the given failInfo, signed by the RA.
    /// </summary>
    public static byte[] EncodeFailure(ScepRequest request, ScepFailInfo failInfo, X509Certificate2 raCertificate) =>
        SignWithoutContent(request, "2", failInfo, raCertificate);

    /// <summary>
    /// Encodes certificates as a degenerate certificates-only CMS SignedData (RFC 8894, 3.4).
    /// </summary>
    public static byte[] EncodeCertificatesOnly(X509Certificate2[] certificates)
    {
        var signedData = new SignedData(version: 1, certificates: certificates);
        var contentInfo = new CmsContentInfo(
            Oids.Pkcs7Signed.InitializeOid(Oids.Pkcs7SignedFriendlyName),
            signedData);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        contentInfo.Encode(writer);
        return writer.Encode();
    }

    private static byte[] Sign(
        byte[] content,
        ScepRequest request,
        string pkiStatus,
        ScepFailInfo? failInfo,
        X509Certificate2 raCertificate)
    {
        var cms = new SignedCms(new CmsContentInfoPkcs(new Oid(ScepOids.Data), content));
        var signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, raCertificate)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1"), // SHA-256
            IncludeOption = X509IncludeOption.EndCertOnly
        };
        signer.SignedAttributes.Add(PrintableString(ScepOids.MessageType,
            ((int)ScepMessageType.CertRep).ToString(CultureInfo.InvariantCulture)));
        signer.SignedAttributes.Add(PrintableString(ScepOids.PkiStatus, pkiStatus));
        signer.SignedAttributes.Add(PrintableString(ScepOids.TransactionId, request.TransactionId));
        signer.SignedAttributes.Add(OctetString(ScepOids.RecipientNonce, request.SenderNonce));
        signer.SignedAttributes.Add(OctetString(ScepOids.SenderNonce, RandomNumberGenerator.GetBytes(16)));
        if (failInfo is { } info)
        {
            signer.SignedAttributes.Add(PrintableString(ScepOids.FailInfo,
                ((int)info).ToString(CultureInfo.InvariantCulture)));
        }

        cms.ComputeSignature(signer);
        return cms.Encode();
    }

    /// <summary>
    /// A CertRep without content (RFC 8894, 3.3.2: a FAILURE carries no pkcsPKIEnvelope).
    /// SignedCms refuses to sign empty content - embedded or detached - so this one is
    /// written by hand: the signature covers the signed attributes, the messageDigest is
    /// the digest of the empty content, and encapContentInfo has no eContent. That is
    /// what micromdm/scep sends for a failure as well.
    /// </summary>
    private static byte[] SignWithoutContent(
        ScepRequest request,
        string pkiStatus,
        ScepFailInfo? failInfo,
        X509Certificate2 raCertificate)
    {
        const string sha256 = "2.16.840.1.101.3.4.2.1";
        const string rsaEncryption = "1.2.840.113549.1.1.1";
        const string contentTypeAttribute = "1.2.840.113549.1.9.3";
        const string messageDigestAttribute = "1.2.840.113549.1.9.4";

        var attributes = new List<(string Oid, byte[] Value)>
        {
            (contentTypeAttribute, EncodeOid(ScepOids.Data)),
            (messageDigestAttribute, EncodeOctets(SHA256.HashData([]))),
            (ScepOids.MessageType, EncodePrintable(((int)ScepMessageType.CertRep).ToString(CultureInfo.InvariantCulture))),
            (ScepOids.PkiStatus, EncodePrintable(pkiStatus)),
            (ScepOids.TransactionId, EncodePrintable(request.TransactionId)),
            (ScepOids.RecipientNonce, EncodeOctets(request.SenderNonce)),
            (ScepOids.SenderNonce, EncodeOctets(RandomNumberGenerator.GetBytes(16)))
        };
        if (failInfo is { } info)
        {
            attributes.Add((ScepOids.FailInfo, EncodePrintable(((int)info).ToString(CultureInfo.InvariantCulture))));
        }

        // The signature is computed over the DER of the attributes as a SET OF (tag 0x31);
        // in the SignerInfo the same bytes carry the implicit tag [0].
        byte[] EncodeAttributes(Asn1Tag? tag)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSetOf(tag);
            foreach (var (oid, value) in attributes)
            {
                writer.PushSequence();
                writer.WriteObjectIdentifier(oid);
                writer.PushSetOf();
                writer.WriteEncodedValue(value);
                writer.PopSetOf();
                writer.PopSequence();
            }

            writer.PopSetOf(tag);
            return writer.Encode();
        }

        using var key = raCertificate.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("The RA certificate has no RSA private key.");
        var signature = key.SignData(EncodeAttributes(null), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var w = new AsnWriter(AsnEncodingRules.DER);
        w.PushSequence(); // ContentInfo
        w.WriteObjectIdentifier(Oids.Pkcs7Signed);
        w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        w.PushSequence(); // SignedData
        w.WriteInteger(1);
        w.PushSetOf();
        WriteAlgorithm(w, sha256, withNullParameters: false);
        w.PopSetOf();
        w.PushSequence(); // encapContentInfo without eContent
        w.WriteObjectIdentifier(ScepOids.Data);
        w.PopSequence();
        w.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)); // certificates
        w.WriteEncodedValue(raCertificate.RawData);
        w.PopSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        w.PushSetOf(); // signerInfos
        w.PushSequence();
        w.WriteInteger(1);
        w.PushSequence(); // IssuerAndSerialNumber
        w.WriteEncodedValue(raCertificate.IssuerName.RawData);
        w.WriteInteger(raCertificate.SerialNumberBytes.Span);
        w.PopSequence();
        WriteAlgorithm(w, sha256, withNullParameters: false);
        w.WriteEncodedValue(EncodeAttributes(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)));
        WriteAlgorithm(w, rsaEncryption, withNullParameters: true);
        w.WriteOctetString(signature);
        w.PopSequence();
        w.PopSetOf();
        w.PopSequence(); // SignedData
        w.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        w.PopSequence(); // ContentInfo
        return w.Encode();
    }

    /// <summary>
    /// SHA-2 identifiers carry no parameters (RFC 5754, section 2: "MUST generate SHA2
    /// AlgorithmIdentifiers with absent parameters"); rsaEncryption carries NULL
    /// (RFC 3370, section 3.2).
    /// </summary>
    private static void WriteAlgorithm(AsnWriter writer, string oid, bool withNullParameters)
    {
        writer.PushSequence();
        writer.WriteObjectIdentifier(oid);
        if (withNullParameters)
        {
            writer.WriteNull();
        }

        writer.PopSequence();
    }

    private static byte[] EncodeOid(string oid)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(oid);
        return writer.Encode();
    }

    private static byte[] EncodeOctets(byte[] value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(value);
        return writer.Encode();
    }

    private static byte[] EncodePrintable(string value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.PrintableString, value);
        return writer.Encode();
    }

    private static AsnEncodedData PrintableString(string oid, string value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.PrintableString, value);
        return new AsnEncodedData(new Oid(oid), writer.Encode());
    }

    private static AsnEncodedData OctetString(string oid, byte[] value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(value);
        return new AsnEncodedData(new Oid(oid), writer.Encode());
    }

    /// <summary>
    /// Reads a string attribute value. RFC 8894 uses PrintableString; some clients send
    /// UTF8String or IA5String, which are accepted as well.
    /// </summary>
    internal static string ReadString(byte[] raw)
    {
        var reader = new AsnReader(raw, AsnEncodingRules.BER);
        var tag = reader.PeekTag();
        var type = tag.TagValue switch
        {
            (int)UniversalTagNumber.UTF8String => UniversalTagNumber.UTF8String,
            (int)UniversalTagNumber.IA5String => UniversalTagNumber.IA5String,
            _ => UniversalTagNumber.PrintableString
        };
        return reader.ReadCharacterString(type);
    }
}
