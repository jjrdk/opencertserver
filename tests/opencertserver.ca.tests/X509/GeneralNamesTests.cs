using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

namespace OpenCertServer.Ca.Tests.X509;

public class GeneralNamesTests
{
    [Fact]
    public void CanReloadGeneralNames()
    {
        var generalNames = new GeneralNames(
            new GeneralName(GeneralName.GeneralNameType.Rfc822Name,
                new AsnString(new Asn1Tag(UniversalTagNumber.IA5String), "test1")),
            new GeneralName(GeneralName.GeneralNameType.DnsName,
                new AsnString(new Asn1Tag(UniversalTagNumber.IA5String), "test2")));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        generalNames.Encode(writer);
        var encoded = writer.Encode();
        var reloaded = new GeneralNames(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Equal(2, reloaded.Names.Length);
        Assert.Equal("test1", reloaded.Names[0].Value.ToString());
        Assert.Equal("test2", reloaded.Names[1].Value.ToString());
    }
}
