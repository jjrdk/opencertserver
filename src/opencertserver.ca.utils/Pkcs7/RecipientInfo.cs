using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Pkcs7;

/// <summary>
/// RFC 5652 RecipientInfo.
/// </summary>
/// <code>
/// RecipientInfo ::= CHOICE {
///   ktri KeyTransRecipientInfo,
///   kari [1] KeyAgreeRecipientInfo,
///   kekri [2] KEKRecipientInfo,
///   pwri [3] PasswordRecipientInfo,
///   ori [4] OtherRecipientInfo
/// }
/// </code>
public sealed class RecipientInfo : IAsnValue
{
    public RecipientInfo(KeyTransRecipientInfo keyTransRecipientInfo)
    {
        KeyTransRecipientInfo = keyTransRecipientInfo;
    }

    public RecipientInfo(byte[] encodedValue)
    {
        EncodedValue = encodedValue.ToArray();
    }

    public RecipientInfo(AsnReader reader)
    {
        var tag = reader.PeekTag();
        if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.Sequence)
        {
            KeyTransRecipientInfo = new KeyTransRecipientInfo(reader);
            return;
        }

        EncodedValue = reader.ReadEncodedValue().ToArray();
    }

    public KeyTransRecipientInfo? KeyTransRecipientInfo { get; }

    public byte[]? EncodedValue { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        if (KeyTransRecipientInfo != null)
        {
            KeyTransRecipientInfo.Encode(writer, tag);
            return;
        }

        if (EncodedValue != null)
        {
            writer.WriteEncodedValue(EncodedValue);
        }
    }
}