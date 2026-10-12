namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using X509;

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
        var writer = new AsnWriter(AsnEncodingRules.DER);
        tbsResponseData.Encode(writer);
        TbsResponseDataBytes = writer.Encode();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="OcspBasicResponse"/> class.
    /// </summary>
    public OcspBasicResponse(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        TbsResponseDataBytes = sequenceReader.PeekEncodedValue().ToArray();
        TbsResponseData = new ResponseData(sequenceReader);
        SignatureAlgorithm = new AlgorithmIdentifier(sequenceReader);
        Signature = sequenceReader.ReadBitString(out _);
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            // certs [0] EXPLICIT SEQUENCE OF Certificate
            var explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            var certsReader = explicitReader.ReadSequence();
            explicitReader.ThrowIfNotEmpty();
            var certs = new List<X509Certificate2>();
            while (certsReader.HasData)
            {
                var certData = certsReader.ReadEncodedValue();
                certs.Add(X509CertificateLoader.LoadCertificate(certData.Span));
            }

            Certs = certs.AsReadOnly();
        }
    }

    /// <summary>
    /// Gets the to-be-signed response data.
    /// </summary>
    public ResponseData TbsResponseData { get; }

    /// <summary>
    /// Gets the signature algorithm used for this OCSP basic response.
    /// </summary>
    public AlgorithmIdentifier SignatureAlgorithm { get; }

    /// <summary>
    /// Gets the response signature bytes.
    /// </summary>
    public byte[] Signature { get; }

    /// <summary>
    /// Gets the DER encoding of <see cref="TbsResponseData"/> as it was signed: the bytes as
    /// received when the response was read, the encoding of the given data otherwise.
    /// </summary>
    /// <remarks>
    /// Verify <see cref="Signature"/> over these bytes, not over a re-encoding of
    /// <see cref="TbsResponseData"/>. Decoding and re-encoding is not byte-exact: .NET reads a
    /// GeneralizedTime with fractional seconds one tick low for some values
    /// (<c>.5174610</c> becomes <c>.5174609</c>; dotnet/runtime#134839, ASN1-GENTIME-1), and a
    /// signature over the re-encoded bytes then fails although the response is genuine.
    /// </remarks>
    public byte[] TbsResponseDataBytes { get; }

    /// <summary>
    /// Gets the optional certificates included with the response.
    /// </summary>
    public IReadOnlyCollection<X509Certificate2>? Certs { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        TbsResponseData.Encode(writer);
        SignatureAlgorithm.Encode(writer);
        writer.WriteBitString(Signature);
        if (Certs is { Count: > 0 })
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (writer.PushSequence())
            {
                foreach (var cert in Certs)
                {
                    writer.WriteEncodedValue(cert.RawData);
                }
            }
        }

        writer.PopSequence(tag);
    }
}
