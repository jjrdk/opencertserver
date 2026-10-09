namespace OpenCertServer.Ca.Utils.Pkcs7;

using System.Formats.Asn1;
using System.Numerics;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the EnvelopedData structure as specified in RFC 5652 section 6.
/// </summary>
/// <code>
/// EnvelopedData ::= SEQUENCE {
///   version CMSVersion,
///   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///   recipientInfos RecipientInfos,
///   encryptedContentInfo EncryptedContentInfo,
///   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
/// }
///
/// RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
/// </code>
public sealed class EnvelopedData : IAsnValue
{
    public EnvelopedData(
        BigInteger version,
        IReadOnlyList<RecipientInfo> recipientInfos,
        EncryptedContentInfo encryptedContentInfo,
        OriginatorInfo? originatorInfo = null,
        UnprotectedAttributes? unprotectedAttributes = null)
    {
        Version = version;
        RecipientInfos = recipientInfos;
        EncryptedContentInfo = encryptedContentInfo;
        OriginatorInfo = originatorInfo;
        UnprotectedAttributes = unprotectedAttributes;
    }

    public EnvelopedData(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Version = sequenceReader.ReadInteger();
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            OriginatorInfo = new OriginatorInfo(
                sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)));
        }

        var recipientInfosReader = sequenceReader.ReadSetOf();
        List<RecipientInfo> recipientInfos = [];
        while (recipientInfosReader.HasData)
        {
            recipientInfos.Add(new RecipientInfo(recipientInfosReader));
        }

        RecipientInfos = recipientInfos.AsReadOnly();
        EncryptedContentInfo = new EncryptedContentInfo(sequenceReader);
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            UnprotectedAttributes = new UnprotectedAttributes(
                sequenceReader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 1)));
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    public BigInteger Version { get; }

    public OriginatorInfo? OriginatorInfo { get; }

    public IReadOnlyList<RecipientInfo> RecipientInfos { get; }

    public EncryptedContentInfo EncryptedContentInfo { get; }

    public UnprotectedAttributes? UnprotectedAttributes { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteInteger(Version);
            OriginatorInfo?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
            using (writer.PushSetOf())
            {
                foreach (var recipientInfo in RecipientInfos)
                {
                    recipientInfo.Encode(writer);
                }
            }

            EncryptedContentInfo.Encode(writer);
            UnprotectedAttributes?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 1));
        }
    }
}
