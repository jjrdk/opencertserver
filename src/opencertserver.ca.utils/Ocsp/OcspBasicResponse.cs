using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Defines an OCSP Basic Response as per RFC 6960.
/// </summary>
/// <code>
/// BasicOCSPResponse       ::= SEQUENCE {
///   tbsResponseData       ResponseData,
///   signatureAlgorithm    AlgorithmIdentifier,
///   signature             BIT STRING,
///   certs                 [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
/// }
/// </code>
public class OcspBasicResponse : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="OcspBasicResponse"/> class.
    /// </summary>
    /// <param name="tbsResponseData"></param>
    /// <param name="signatureAlgorithm"></param>
    /// <param name="signature"></param>
    /// <param name="certs"></param>
    public OcspBasicResponse(
        ResponseData tbsResponseData,
        AlgorithmIdentifier signatureAlgorithm,
        byte[] signature,
        IEnumerable<X509Certificate2>? certs = null)
    {
        TbsResponseData = tbsResponseData;
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
        Certs = certs == null ? [] : certs.ToArray().AsReadOnly();
    }

    public OcspBasicResponse(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        TbsResponseData = new ResponseData(sequenceReader);
        SignatureAlgorithm = new AlgorithmIdentifier(sequenceReader);
        Signature = sequenceReader.ReadBitString(out _);
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            var certsReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            var certs = new List<X509Certificate2>();
            while (certsReader.HasData)
            {
                var certData = certsReader.ReadEncodedValue();
                certs.Add(X509CertificateLoader.LoadCertificate(certData.Span));
            }

            Certs = certs.AsReadOnly();
        }
    }

    public ResponseData TbsResponseData { get; }

    public AlgorithmIdentifier SignatureAlgorithm { get; }

    public byte[] Signature { get; }

    public IReadOnlyCollection<X509Certificate2>? Certs { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        TbsResponseData.Encode(writer);
        SignatureAlgorithm.Encode(writer);
        writer.WriteBitString(Signature);
        if (Certs is { Count: > 0 })
        {
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            foreach (var cert in Certs)
            {
                writer.WriteEncodedValue(cert.RawData);
            }

            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        }

        writer.PopSequence(tag);
    }
}
