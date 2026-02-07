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
        var atv = new AttributeTypeValue(Oids.CommonName.InitializeOid(),
            new Asn1Tag(TagClass.ContextSpecific, (int)UniversalTagNumber.UTF8String), "TestValue"u8);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        atv.Encode(writer);
        var encoded = writer.Encode();
        var reloaded = new AttributeTypeValue(new AsnReader(encoded, AsnEncodingRules.DER));
        Assert.Equal(Oids.CommonName.InitializeOid(), reloaded.Oid, OidComparer.Instance);
        Assert.Equal("TestValue", reloaded.Value);
    }
}
