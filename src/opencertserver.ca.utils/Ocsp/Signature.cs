namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines a Signature specification
/// </summary>
/// <code>
/// SEQUENCE {
///     signatureAlgorithm      AlgorithmIdentifier,
///     signature               BIT STRING,
///     certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
/// }
/// </code>
public class Signature : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Signature"/> class.
    /// </summary>
    public Signature(AlgorithmIdentifier algorithmIdentifier, byte[] signature, IList<X509Certificate2>? certs = null)
    {
        AlgorithmIdentifier = algorithmIdentifier;
        SignatureBytes = signature;
        Certs = certs;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="Signature"/> class.
    /// </summary>
    public Signature(AsnReader reader, Asn1Tag? expectedTag = null)
    {
        var sequenceReader = reader.ReadSequence(expectedTag);
        AlgorithmIdentifier = new AlgorithmIdentifier(sequenceReader);
        SignatureBytes = sequenceReader.ReadBitString(out _);
        if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            var certsReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            var certs = new List<X509Certificate2>();
            while (certsReader.HasData)
            {
                var certBytes = certsReader.ReadEncodedValue();
                certs.Add(X509CertificateLoader.LoadCertificate(certBytes.Span));
            }

            Certs = certs;
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    /// <summary>
    /// Gets the signature algorithm identifier.
    /// </summary>
    public AlgorithmIdentifier AlgorithmIdentifier { get; }

    /// <summary>
    /// Gets the signature bytes.
    /// </summary>
    public byte[] SignatureBytes { get; }

    /// <summary>
    /// Gets the optional certificate chain used to verify the signature.
    /// </summary>
    public IList<X509Certificate2>? Certs { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        AlgorithmIdentifier.Encode(writer);
        writer.WriteBitString(SignatureBytes);
        if (Certs != null)
        {
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            foreach (var cert in Certs)
            {
                writer.WriteEncodedValue(cert.RawData);
            }

            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        writer.PopSequence(tag);
    }
}
