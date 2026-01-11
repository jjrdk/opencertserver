namespace OpenCertServer.Ca.Tests.X509;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

public class RelativeDistinguishedNameTests
{
    [Fact]
    public void CanReloadRelativeDistinguishedName()
    {
        var rdn = new RelativeDistinguishedName(
            new AttributeTypeValue(Oids.OrganizationalUnitOid,
                new Asn1Tag(TagClass.ContextSpecific, (int)UniversalTagNumber.UTF8String), "PartyNameValue"u8)
        );
        var writer = new AsnWriter(AsnEncodingRules.DER);
        rdn.Encode(writer);
        var encoded = writer.Encode();
        var reloaded = new RelativeDistinguishedName(new AsnReader(encoded, AsnEncodingRules.DER));

        var value = reloaded.Values.First();

        Assert.Equal(Oids.OrganizationalUnitOid, value.Oid, new OidComparer());
        Assert.Equal("PartyNameValue", value.Value);
    }
}
