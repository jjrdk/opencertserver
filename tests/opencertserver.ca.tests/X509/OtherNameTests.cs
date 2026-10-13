namespace OpenCertServer.Ca.Tests.X509;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

public class OtherNameTests
{
    [Fact]
    public void CanReloadOtherNameWithUtf8StringValue()
    {
        var innerWriter = new AsnWriter(AsnEncodingRules.DER);
        innerWriter.WriteCharacterString(UniversalTagNumber.UTF8String, "alice@example.com");
        var otherName = new OtherName(Oids.UserPrincipalName, innerWriter.Encode());

        var writer = new AsnWriter(AsnEncodingRules.DER);
        otherName.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
        var encoded = writer.Encode();

        var reader = new AsnReader(encoded, AsnEncodingRules.DER);
        var reloaded = new OtherName(reader);

        Assert.Equal(Oids.UserPrincipalName, reloaded.TypeId);
        Assert.Equal("alice@example.com", reloaded.StringValue);
    }

    [Fact]
    public void OtherNameWithNonStringValueHasNullStringValue()
    {
        var innerWriter = new AsnWriter(AsnEncodingRules.DER);
        innerWriter.WriteInteger(42);
        var otherName = new OtherName("1.2.3.4", innerWriter.Encode());

        var writer = new AsnWriter(AsnEncodingRules.DER);
        otherName.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
        var encoded = writer.Encode();

        var reloaded = new OtherName(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Equal("1.2.3.4", reloaded.TypeId);
        Assert.Null(reloaded.StringValue);
    }
}
