using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

namespace OpenCertServer.Ca.Tests.X509;

public class GeneralNameTests
{
    [Fact]
    public void CanReloadGeneralName()
    {
        var generalName = new GeneralName(GeneralName.GeneralNameType.Rfc822Name,
            new AsnString(new Asn1Tag(UniversalTagNumber.IA5String), "test"));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        generalName.Encode(writer);
        var encoded = writer.Encode();
        var reloaded = new GeneralName(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Equal("test", reloaded.Value.ToString());
    }
}
