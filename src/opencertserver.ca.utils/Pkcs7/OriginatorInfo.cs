using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Pkcs7;

/// <summary>
/// Defines the OriginatorInfo structure as specified in RFC 5652 section 6.
/// </summary>
/// <code>
/// OriginatorInfo ::= SEQUENCE {
///   certs [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL
/// }
/// </code>
public sealed class OriginatorInfo : IAsnValue
{
    public OriginatorInfo(X509Certificate2Collection? certs = null, RevocationInfoChoices? crls = null)
    {
        Certs = certs;
        Crls = crls;
    }

    public OriginatorInfo(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            var certsReader = sequenceReader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));
            var certs = new X509Certificate2Collection();
            while (certsReader.HasData)
            {
                certs.Add(X509CertificateLoader.LoadCertificate(certsReader.ReadEncodedValue().Span));
            }

            Certs = certs;
        }

        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            Crls = new RevocationInfoChoices(
                sequenceReader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)));
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    public X509Certificate2Collection? Certs { get; }

    public RevocationInfoChoices? Crls { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            if (Certs is { Count: > 0 })
            {
                using (writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    foreach (var cert in Certs)
                    {
                        writer.WriteEncodedValue(cert.RawData);
                    }
                }
            }

            if (Crls != null)
            {
                Crls.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 1));
            }
        }
    }
}