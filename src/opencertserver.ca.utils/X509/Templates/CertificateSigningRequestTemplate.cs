using System.Formats.Asn1;
using System.Numerics;

namespace OpenCertServer.Ca.Utils.X509.Templates;

public class CertificateSigningRequestTemplate : AsnValue
{
    /*
    CertificationRequestInfoTemplate ::= SEQUENCE {
       version INTEGER { v1(0) } (v1, ... ),
       subject NameTemplate OPTIONAL,
       subjectPKInfo [0] SubjectPublicKeyInfoTemplate {{ PKInfoAlgorithms }} OPTIONAL,
       attributes [1] Attributes{{ CRIAttributes }}
    }
     */

    public CertificateSigningRequestTemplate(
        BigInteger version,
        NameTemplate? subject = null,
        SubjectPublicKeyInfoTemplate? subjectPkInfo = null)
    {
        // TODO: Support CRIAttributes
        Version = version;
        Subject = subject;
        SubjectPublicKeyInfo = subjectPkInfo;
    }

    public CertificateSigningRequestTemplate(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Version = sequenceReader.ReadInteger();
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.Sequence)))
        {
            Subject = new NameTemplate(sequenceReader);
        }

        if (sequenceReader.HasData)
        {
            var tag = sequenceReader.PeekTag();
            if (sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                SubjectPublicKeyInfo = new SubjectPublicKeyInfoTemplate(sequenceReader, tag);
            }
        }
    }

    public BigInteger Version { get; }

    public NameTemplate? Subject { get; }

    public SubjectPublicKeyInfoTemplate? SubjectPublicKeyInfo { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence())
        {
            writer.WriteInteger(Version);
            Subject?.Encode(writer);
            SubjectPublicKeyInfo?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
        }
    }
}
