using System.Formats.Asn1;
using System.Numerics;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Pkcs7;

/// <summary>
/// RFC 5652 KeyTransRecipientInfo.
/// </summary>
/// <code>
/// KeyTransRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 0 or 2
///   rid RecipientIdentifier,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey
/// }
///
/// EncryptedKey ::= OCTET STRING
/// </code>
public sealed class KeyTransRecipientInfo : IAsnValue
{
    public KeyTransRecipientInfo(
        BigInteger version,
        RecipientIdentifier rid,
        CmsAlgorithmIdentifier keyEncryptionAlgorithm,
        byte[] encryptedKey)
    {
        Version = version;
        Rid = rid;
        KeyEncryptionAlgorithm = keyEncryptionAlgorithm;
        EncryptedKey = encryptedKey.ToArray();
    }

    public KeyTransRecipientInfo(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Version = sequenceReader.ReadInteger();
        Rid = new RecipientIdentifier(sequenceReader);
        KeyEncryptionAlgorithm = new CmsAlgorithmIdentifier(sequenceReader);
        EncryptedKey = sequenceReader.ReadOctetString();
        sequenceReader.ThrowIfNotEmpty();
    }

    public BigInteger Version { get; }

    public RecipientIdentifier Rid { get; }

    public CmsAlgorithmIdentifier KeyEncryptionAlgorithm { get; }

    public byte[] EncryptedKey { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteInteger(Version);
            Rid.Encode(writer);
            KeyEncryptionAlgorithm.Encode(writer);
            writer.WriteOctetString(EncryptedKey);
        }
    }
}