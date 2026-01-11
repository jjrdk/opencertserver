namespace OpenCertServer.Ca.Tests.X509;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

public class DistributionPointNameTests
{
    [Fact]
    public void CanReloadDistributionPointName()
    {
        var dpn = new DistributionPointName(DistributionPointName.DistributionPointNameType.NameRelativeToCrlIssuer,
            new RelativeDistinguishedName(
                new AttributeTypeValue(Oids.OrganizationalUnitOid,
                    new Asn1Tag(TagClass.ContextSpecific, (int)UniversalTagNumber.UTF8String), "PartyNameValue"u8)
            ));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        dpn.Encode(writer, null);
        var encoded = writer.Encode();
        var reloaded = new DistributionPointName(new AsnReader(encoded, AsnEncodingRules.DER));

        var value = reloaded.NameRelativeToCrlIssuer?.Values.First();

        Assert.Equal(Oids.OrganizationalUnitOid, value?.Oid!, new OidComparer());
        Assert.Equal("PartyNameValue", value?.Value);
        Assert.Null(reloaded.FullName);
    }
}
