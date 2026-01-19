using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils;

public class X500DistinguishedNameTemplate
{
    public X500DistinguishedNameTemplate(IEnumerable<RelativeDistinguishedName> relativeDistinguishedNames)
    {
        RelativeNames = relativeDistinguishedNames.ToArray();
    }

    public RelativeDistinguishedName[] RelativeNames { get; }

    public static X500DistinguishedNameTemplate Read(AsnReader reader)
    {
        var seqReader = reader.ReadSequence();
        while (seqReader.HasData)
        {
            
        }

        return new X500DistinguishedNameTemplate([]);
    }
}
