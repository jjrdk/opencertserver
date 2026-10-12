namespace OpenCertServer.Ca.Tests.X509;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

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

    [Fact]
    public void CanReloadGeneralNameWithOtherNameUserPrincipalName()
    {
        var innerWriter = new AsnWriter(AsnEncodingRules.DER);
        innerWriter.WriteCharacterString(UniversalTagNumber.UTF8String, "alice@example.com");
        var generalName = new GeneralName(GeneralName.GeneralNameType.OtherName,
            new OtherName(Oids.UserPrincipalName, innerWriter.Encode()));

        var writer = new AsnWriter(AsnEncodingRules.DER);
        generalName.Encode(writer);
        var encoded = writer.Encode();
        var reloaded = new GeneralName(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Equal(GeneralName.GeneralNameType.OtherName, reloaded.Type);
        var otherName = Assert.IsType<OtherName>(reloaded.Value);
        Assert.Equal(Oids.UserPrincipalName, otherName.TypeId);
        Assert.Equal("alice@example.com", otherName.StringValue);
    }
}