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

    public BigInteger Version { get; }

    public NameTemplate? Subject { get; }

    public SubjectPublicKeyInfoTemplate? SubjectPublicKeyInfo { get; }

    public static CertificateSigningRequestTemplate Read(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        var version = sequenceReader.ReadInteger();
        NameTemplate? subject = null;
        SubjectPublicKeyInfoTemplate? subjectPkInfo = null;
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.Sequence)))
        {
            subject = new NameTemplate(sequenceReader);
        }

        if (sequenceReader.HasData)
        {
            var tag = sequenceReader.PeekTag();
            if (sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                subjectPkInfo = new SubjectPublicKeyInfoTemplate(sequenceReader, tag);
            }
        }

        return new CertificateSigningRequestTemplate(version, subject, subjectPkInfo);
    }

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
