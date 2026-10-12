namespace OpenCertServer.Ca.Tests.X509;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

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

    [Fact]
    public void CanParseGeneralNamesWithUserPrincipalNameOtherNameMixedWithDnsName()
    {
        // Regression test: a single otherName (e.g. UPN) entry in a SAN previously
        // threw AsnContentException and aborted parsing of the whole SAN list,
        // including unrelated dnsName entries.
        var innerWriter = new AsnWriter(AsnEncodingRules.DER);
        innerWriter.WriteCharacterString(UniversalTagNumber.UTF8String, "alice@example.com");
        var generalNames = new GeneralNames(
            new GeneralName(GeneralName.GeneralNameType.OtherName,
                new OtherName(Oids.UserPrincipalName, innerWriter.Encode())),
            new GeneralName(GeneralName.GeneralNameType.DnsName,
                new AsnString(new Asn1Tag(UniversalTagNumber.IA5String), "www.example.com")));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        generalNames.Encode(writer);
        var encoded = writer.Encode();

        var reloaded = new GeneralNames(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Equal(2, reloaded.Names.Length);
        var otherName = Assert.IsType<OtherName>(reloaded.Names[0].Value);
        Assert.Equal("alice@example.com", otherName.StringValue);
        Assert.Equal("www.example.com", reloaded.Names[1].Value.ToString());
    }
}