namespace OpenCertServer.Scep.Tests;

using System.Formats.Asn1;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Scep.Server;

/// <summary>
/// A minimal SCEP client for the tests. It builds real messages - signed with a
/// self-signed certificate, the CSR encrypted to the RA - the way a device does,
/// so the server is exercised over HTTP and not through its own codec.
/// </summary>
public sealed class ScepTestClient(HttpClient http, string path = "/scep")
{
    public async Task<string> GetCaCaps() =>
        await http.GetStringAsync($"{path}?operation=GetCACaps").ConfigureAwait(false);

    public async Task<(string ContentType, X509Certificate2Collection Certificates)> GetCaCert()
    {
        var response = await http.GetAsync($"{path}?operation=GetCACert").ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        var cms = new SignedCms();
        cms.Decode(bytes);
        return (response.Content.Headers.ContentType?.MediaType ?? "", cms.Certificates);
    }

    /// <summary>
    /// Builds and sends a PKCSReq (19) or, signed with the certificate it renews, a
    /// RenewalReq (17); returns the HTTP response.
    /// </summary>
    public async Task<HttpResponseMessage> Enroll(
        CertificateRequest csr,
        X509Certificate2 signer,
        X509Certificate2 recipient,
        string transactionId,
        byte[] senderNonce,
        bool useGet = false,
        string messageType = "19",
        string encryptionOid = OpenCertServer.Ca.Utils.Oids.Aes128Cbc)
    {
        var csrDer = csr.CreateSigningRequest();
        var enveloped = new EnvelopedCms(
            new ContentInfo(csrDer),
            new AlgorithmIdentifier(new System.Security.Cryptography.Oid(encryptionOid)));
        enveloped.Encrypt(new CmsRecipient(SubjectIdentifierType.IssuerAndSerialNumber, recipient));

        var signed = new SignedCms(new ContentInfo(enveloped.Encode()));
        var cmsSigner = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, signer)
        {
            DigestAlgorithm = new System.Security.Cryptography.Oid("2.16.840.1.101.3.4.2.1")
        };
        cmsSigner.SignedAttributes.Add(Printable(ScepOids.MessageType, messageType));
        cmsSigner.SignedAttributes.Add(Printable(ScepOids.TransactionId, transactionId));
        cmsSigner.SignedAttributes.Add(Octets(ScepOids.SenderNonce, senderNonce));
        signed.ComputeSignature(cmsSigner);
        var message = signed.Encode();

        if (useGet)
        {
            var encoded = Uri.EscapeDataString(Convert.ToBase64String(message));
            return await http.GetAsync($"{path}?operation=PKIOperation&message={encoded}").ConfigureAwait(false);
        }

        using var content = new ByteArrayContent(message);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-pki-message");
        return await http.PostAsync($"{path}?operation=PKIOperation", content).ConfigureAwait(false);
    }

    /// <summary>A CSR with an RSA key and, if given, a challenge password.</summary>
    public static CertificateRequest CreateCsr(RSA key, string subject, string? challenge)
    {
        var csr = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (challenge is not null)
        {
            csr.OtherRequestAttributes.Add(Printable(ScepOids.ChallengePassword, challenge));
        }

        return csr;
    }

    /// <summary>The transient, self-signed certificate a SCEP client signs its first request with.</summary>
    public static X509Certificate2 CreateTransientSigner(RSA key)
    {
        var request = new CertificateRequest("CN=SCEP transient", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static AsnEncodedData Printable(string oid, string value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.PrintableString, value);
        return new AsnEncodedData(new System.Security.Cryptography.Oid(oid), writer.Encode());
    }

    private static AsnEncodedData Octets(string oid, byte[] value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteOctetString(value);
        return new AsnEncodedData(new System.Security.Cryptography.Oid(oid), writer.Encode());
    }
}

/// <summary>A decoded CertRep as the client sees it.</summary>
public sealed record ScepTestResponse(
    string MessageType,
    string PkiStatus,
    string? FailInfo,
    string TransactionId,
    byte[] RecipientNonce,
    X509Certificate2? Issued,
    string? EncryptionAlgorithm)
{
    /// <summary>Verifies and decodes a CertRep; decrypts the certificate with the client's key.</summary>
    public static ScepTestResponse Read(byte[] body, X509Certificate2 clientSigner)
    {
        var signed = new SignedCms();
        signed.Decode(body);
        signed.CheckSignature(verifySignatureOnly: true);
        var signer = signed.SignerInfos[0];
        string? messageType = null, pkiStatus = null, failInfo = null, transactionId = null;
        byte[] recipientNonce = [];
        foreach (var attribute in signer.SignedAttributes)
        {
            var raw = attribute.Values[0].RawData;
            switch (attribute.Oid.Value)
            {
                case ScepOids.MessageType: messageType = ReadPrintable(raw); break;
                case ScepOids.PkiStatus: pkiStatus = ReadPrintable(raw); break;
                case ScepOids.FailInfo: failInfo = ReadPrintable(raw); break;
                case ScepOids.TransactionId: transactionId = ReadPrintable(raw); break;
                case ScepOids.RecipientNonce: recipientNonce = new AsnReader(raw, AsnEncodingRules.BER).ReadOctetString(); break;
            }
        }

        X509Certificate2? issued = null;
        string? encryption = null;
        if (pkiStatus == "0")
        {
            var enveloped = new EnvelopedCms();
            enveloped.Decode(signed.ContentInfo.Content);
            encryption = enveloped.ContentEncryptionAlgorithm.Oid.Value;
            enveloped.Decrypt(new X509Certificate2Collection(clientSigner));
            var certsOnly = new SignedCms();
            certsOnly.Decode(enveloped.ContentInfo.Content);
            issued = certsOnly.Certificates[0];
        }

        return new ScepTestResponse(messageType!, pkiStatus!, failInfo, transactionId!, recipientNonce, issued, encryption);
    }

    private static string ReadPrintable(byte[] raw) =>
        new AsnReader(raw, AsnEncodingRules.BER).ReadCharacterString(UniversalTagNumber.PrintableString);
}
