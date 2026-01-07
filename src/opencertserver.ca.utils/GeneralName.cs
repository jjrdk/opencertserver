using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OpenCertServer.Ca.Utils;

/**
     * The GeneralName object.
     * <pre>
     * GeneralName ::= CHOICE {
     *      otherName                       [0]     OtherName,
     *      rfc822Name                      [1]     IA5String,
     *      dNSName                         [2]     IA5String,
     *      x400Address                     [3]     ORAddress,
     *      directoryName                   [4]     Name,
     *      ediPartyName                    [5]     EDIPartyName,
     *      uniformResourceIdentifier       [6]     IA5String,
     *      iPAddress                       [7]     OCTET STRING,
     *      registeredID                    [8]     OBJECT IDENTIFIER}
     *
     * OtherName ::= Sequence {
     *      type-id    OBJECT IDENTIFIER,
     *      value      [0] EXPLICIT ANY DEFINED BY type-id }
     *
     * EDIPartyName ::= Sequence {
     *      nameAssigner            [0]     DirectoryString OPTIONAL,
     *      partyName               [1]     DirectoryString }
     * </pre>
     */
public class GeneralName
{
    public const int OtherName = 0;
    public const int Rfc822Name = 1;
    public const int DnsName = 2;
    public const int X400Address = 3;
    public const int DirectoryName = 4;
    public const int EdiPartyName = 5;
    public const int UniformResourceIdentifier = 6;
    public const int IPAddress = 7;
    public const int RegisteredID = 8;

    private readonly int _tag;
    private readonly AsnEncodedData _value;

    public GeneralName(X500DistinguishedName directoryName)
    {
        _tag = DirectoryName;
        _value = directoryName;
    }

    /**
     * When the subjectAltName extension contains an Internet mail address,
     * the address MUST be included as an rfc822Name. The format of an
     * rfc822Name is an "addr-spec" as defined in RFC 822 [RFC 822].
     *
     * When the subjectAltName extension contains a domain name service
     * label, the domain name MUST be stored in the dNSName (an IA5String).
     * The name MUST be in the "preferred name syntax," as specified by RFC
     * 1034 [RFC 1034].
     *
     * When the subjectAltName extension contains a URI, the name MUST be
     * stored in the uniformResourceIdentifier (an IA5String). The name MUST
     * be a non-relative URL, and MUST follow the URL syntax and encoding
     * rules specified in [RFC 1738].  The name must include both a scheme
     * (e.g., "http" or "ftp") and a scheme-specific-part.  The scheme-
     * specific-part must include a fully qualified domain name or IP
     * address as the host.
     *
     * When the subjectAltName extension contains a iPAddress, the address
     * MUST be stored in the octet string in "network byte order," as
     * specified in RFC 791 [RFC 791]. The least significant bit (LSB) of
     * each octet is the LSB of the corresponding byte in the network
     * address. For IP Version 4, as specified in RFC 791, the octet string
     * MUST contain exactly four octets.  For IP Version 6, as specified in
     * RFC 1883, the octet string MUST contain exactly sixteen octets [RFC
     * 1883].
     */
    public GeneralName(AsnEncodedData name, int tag)
    {
        _tag = tag;
        _value = name;
    }

    /**
     * Create a GeneralName for the given tag from the passed in string.
     * <p>
     * This constructor can handle:
     * <ul>
     * <li>rfc822Name</li>
     * <li>iPAddress</li>
     * <li>directoryName</li>
     * <li>dNSName</li>
     * <li>uniformResourceIdentifier</li>
     * <li>registeredID</li>
     * </ul>
     * For x400Address, otherName and ediPartyName there is no common string
     * format defined.
     * </p><p>
     * Note: A directory name can be encoded in different ways into a byte
     * representation. Be aware of this if the byte representation is used for
     * comparing results.
     * </p>
     *
     * @param tag tag number
     * @param name string representation of name
     * @throws ArgumentException if the string encoding is not correct or
     *             not supported.
     */
    public GeneralName(int tag, string name)
    {
        _tag = tag;

        switch (tag)
        {
            case DnsName:
            case Rfc822Name:
            case UniformResourceIdentifier:
                _value = new DerIA5String(name);
                break;

            case DirectoryName:
                _value = new X500DistinguishedName(name);
                break;

            case IPAddress:
            {
                byte[] encoding = ToGeneralNameEncoding(name)
                 ?? throw new ArgumentException("IP Address is invalid", nameof(name));

                _value = new DerOctetString(encoding);
                break;
            }

            case RegisteredID:
                _value = new DerObjectIdentifier(name);
                break;

            case EdiPartyName:
            case OtherName:
            case X400Address:
            default:
            {
                string message = string.Format("can't process string for tag: {0}",
                    Asn1Utilities.GetTagText(Asn1Tags.ContextSpecific, tag));

                throw new ArgumentException(message, nameof(tag));
            }
        }
    }

    public int TagNo => _tag;

    public AsnEncodedData Name => _value;

    public override string ToString()
    {
        StringBuilder buf = new StringBuilder();
        buf.Append(_tag);
        buf.Append(": ");

        switch (_tag)
        {
            case Rfc822Name:
            case DnsName:
            case UniformResourceIdentifier:
                buf.Append(DerIA5String.GetInstance(_value).GetString());
                break;
            case DirectoryName:
                buf.Append(new X500DistinguishedName(_value));
                break;
            default:
                buf.Append(_value.ToString());
                break;
        }

        return buf.ToString();
    }

    private byte[]? ToGeneralNameEncoding(string ip)
    {
        return System.Net.IPAddress.TryParse(ip, out var address) ? address.GetAddressBytes() : null;
    }
}
