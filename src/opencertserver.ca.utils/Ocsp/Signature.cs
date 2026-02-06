using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

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
    public Signature(AlgorithmIdentifier algorithmIdentifier, byte[] signature, IList<X509Certificate2>? certs = null)
    {
        AlgorithmIdentifier = algorithmIdentifier;
        SignatureBytes = signature;
        Certs = certs;
    }

    public Signature(AsnReader reader)
    {
        AlgorithmIdentifier = new AlgorithmIdentifier(reader);
        SignatureBytes = reader.ReadBitString(out _);
        if (reader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            var certsReader = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            var certs = new List<X509Certificate2>();
            while (certsReader.HasData)
            {
                var certBytes = certsReader.ReadEncodedValue();
                certs.Add(X509CertificateLoader.LoadCertificate(certBytes.Span));
            }

            Certs = certs;
        }

        reader.ThrowIfNotEmpty();
    }

    public AlgorithmIdentifier AlgorithmIdentifier { get; }

    public byte[] SignatureBytes { get; }

    public IList<X509Certificate2>? Certs { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
    }
}