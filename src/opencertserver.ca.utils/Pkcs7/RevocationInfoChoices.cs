using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Pkcs7;

/// <summary>
/// RFC 5652 RevocationInfoChoices.
/// </summary>
/// <code>
/// RevocationInfoChoices ::= SET OF RevocationInfoChoice
/// RevocationInfoChoice ::= CHOICE {
///   crl CertificateList,
///   other [1] IMPLICIT OtherRevocationInfoFormat
/// }
/// </code>
public sealed class RevocationInfoChoices : IAsnValue
{
    public RevocationInfoChoices(IEnumerable<byte[]> values)
    {
        Values = values.Select(v => v.ToArray()).ToArray();
    }

    public RevocationInfoChoices(AsnReader reader)
    {
        var setReader = reader.ReadSetOf();
        List<byte[]> values = [];
        while (setReader.HasData)
        {
            values.Add(setReader.ReadEncodedValue().ToArray());
        }

        Values = values;
    }

    public IReadOnlyList<byte[]> Values { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSetOf(tag))
        {
            foreach (var value in Values)
            {
                writer.WriteEncodedValue(value);
            }
        }
    }
}