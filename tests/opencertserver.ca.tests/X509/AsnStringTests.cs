using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

namespace OpenCertServer.Ca.Tests.X509;

public class AsnStringTests
{
    [Fact]
    public void CanReloadAsnString()
    {
        var asn1Tag = new Asn1Tag(UniversalTagNumber.IA5String);
        var asnString = new AsnString(asn1Tag, "TestValue");
        var writer = new AsnWriter(AsnEncodingRules.DER);
        asnString.Encode(writer);
        var encoded = writer.Encode();
        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        var tag = reader.PeekTag();
        var reloaded = new AsnString(tag, reader.ReadCharacterString(UniversalTagNumber.IA5String));

        Assert.Equal("TestValue", reloaded.Value);
    }
}
