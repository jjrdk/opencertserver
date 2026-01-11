using System.Formats.Asn1;

namespace OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the GeneralName class.
/// </summary>
/// <remarks>
/// GeneralName ::= CHOICE {
///           otherName                       [0]     OtherName,
///           rfc822Name                      [1]     IA5String,
///           dNSName                         [2]     IA5String,
///           x400Address                     [3]     ORAddress,
///           directoryName                   [4]     Name,
///           ediPartyName                    [5]     EDIPartyName,
///           uniformResourceIdentifier       [6]     IA5String,
///           iPAddress                       [7]     OCTET STRING,
///           registeredID                    [8]     OBJECT IDENTIFIER
/// }
/// </remarks>
public class GeneralName : AsnValue
{
    public enum GeneralNameType
    {
        OtherName = 0,
        Rfc822Name = 1,
        DnsName = 2,
        X400Address = 3,
        DirectoryName = 4,
        EdiPartyName = 5,
        UniformResourceIdentifier = 6,
        IpAddress = 7,
        RegisteredID = 8
    }

    public GeneralName(AsnReader obj)
    {
        var tag = obj.PeekTag();
        if (tag.TagClass != TagClass.ContextSpecific)
        {
            throw new ArgumentException("Invalid GeneralName encoding", nameof(obj));
        }

        Type = (GeneralNameType)tag.TagValue;
        Value = (tag.TagValue) switch
        {
            0 /*otherName*/ => new AsnString(tag, obj.ReadObjectIdentifier()),
            1 /*rfc822Name*/ or 2 /*dnsName*/ or 6 /*uniformResourceIdentifier*/
                => new AsnString(tag, obj.ReadCharacterString(UniversalTagNumber.IA5String, tag)),
            4 /*directoryName*/ => new X509Name(obj.ReadEncodedValue()),
            3 /*x400Address*/ => new AsnString(tag, obj.ReadCharacterString(UniversalTagNumber.UTF8String, tag)),
            5 /*ediPartyName*/ => new EdiPartyName(obj),
            7 /*ipAddress*/ => new AsnString(tag, obj.ReadCharacterString(UniversalTagNumber.OctetString, tag)),
            8 /*registeredID*/ => new AsnString(tag, obj.ReadObjectIdentifier()),
            _ => throw new ArgumentException("Invalid GeneralName tag", nameof(obj))
        };
    }

    public GeneralName(GeneralNameType type, AsnString value)
    {
        Type = type;
        Value = value;
    }

    public GeneralNameType Type { get; }

    public AsnValue Value { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        Value.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, (int)Type));
    }
}
