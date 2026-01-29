namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;

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
public class GeneralName : IAsnValue
{
    /// <summary>
    /// Defines the GeneralNameType enumeration.
    /// </summary>
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
        RegisteredId = 8
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GeneralName"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
    /// <exception cref="ArgumentException">Thrown if the initial tag is content specific.</exception>
    public GeneralName(AsnReader reader)
    {
        var tag = reader.PeekTag();
        if (tag.TagClass != TagClass.ContextSpecific)
        {
            throw new ArgumentException("Invalid GeneralName encoding", nameof(reader));
        }

        Type = (GeneralNameType)tag.TagValue;
        Value = tag.TagValue switch
        {
            0 /*otherName*/ => new AsnString(tag, reader.ReadObjectIdentifier()),
            1 /*rfc822Name*/ or 2 /*dnsName*/ or 6 /*uniformResourceIdentifier*/
                => new AsnString(tag, reader.ReadCharacterString(UniversalTagNumber.IA5String, tag)),
            4 /*directoryName*/ => new X509Name(reader.ReadEncodedValue()),
            3 /*x400Address*/ => new AsnString(tag, reader.ReadCharacterString(UniversalTagNumber.UTF8String, tag)),
            5 /*ediPartyName*/ => new EdiPartyName(reader),
            7 /*ipAddress*/ => new AsnString(tag, reader.ReadCharacterString(UniversalTagNumber.OctetString, tag)),
            8 /*registeredID*/ => new AsnString(tag, reader.ReadObjectIdentifier()),
            _ => throw new ArgumentException("Invalid GeneralName tag", nameof(reader))
        };
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="GeneralName"/> class.
    /// </summary>
    /// <param name="type">The general name type.</param>
    /// <param name="value">The general name value.</param>
    public GeneralName(GeneralNameType type, AsnString value)
    {
        Type = type;
        Value = value;
    }

    /// <summary>
    /// Gets the type of the GeneralName.
    /// </summary>
    public GeneralNameType Type { get; }

    /// <summary>
    /// Gets the value of the GeneralName.
    /// </summary>
    public IAsnValue Value { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        Value.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, (int)Type));
    }
}
