namespace OpenCertServer.Ca.Tests.X509;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

public class X509NameTests
{
    [Fact]
    public void CanReloadX509Name()
    {
        var x509Name = new X509Name(
            new RelativeDistinguishedName(
                new AttributeTypeValue(Oids.OrganizationalUnitOid,
                    new Asn1Tag(TagClass.ContextSpecific, (int)UniversalTagNumber.UTF8String), "PartyNameValue"u8)
            ));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        x509Name.Encode(writer);
        var encoded = writer.Encode();
        var reloaded = new X509Name(new AsnReader(encoded, AsnEncodingRules.DER));

        var rdn = reloaded.RelativeDistinguishedNames.First();
        var value = rdn.Values.First();

        Assert.Equal(Oids.OrganizationalUnitOid, value.Oid, OidComparer.Instance);
        Assert.Equal("PartyNameValue", value.Value);
    }
}
