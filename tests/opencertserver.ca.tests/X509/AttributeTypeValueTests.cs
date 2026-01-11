using System.Formats.Asn1;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

namespace OpenCertServer.Ca.Tests.X509;

public class AttributeTypeValueTests
{
    [Fact]
    public void CanReloadAttributeTypeValue()
    {
        var atv = new AttributeTypeValue(Oids.CommonNameOid,
            new Asn1Tag(TagClass.ContextSpecific, (int)UniversalTagNumber.UTF8String), "TestValue"u8);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        atv.Encode(writer, null);
        var encoded = writer.Encode();
        var reloaded = new AttributeTypeValue(new AsnReader(encoded, AsnEncodingRules.DER));
        Assert.Equal(Oids.CommonNameOid, reloaded.Oid, new OidComparer());
        Assert.Equal("TestValue", reloaded.Value);
    }
}
