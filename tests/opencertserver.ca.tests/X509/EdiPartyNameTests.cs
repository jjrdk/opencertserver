using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

namespace OpenCertServer.Ca.Tests.X509;

public class EdiPartyNameTests
{
    [Fact]
    public void CanReloadEdiPartyNameWithNameAssigner()
    {
        var ediPartyName = new EdiPartyName(
            new DirectoryString("partyName", UniversalTagNumber.TeletexString),
            new DirectoryString("nameAssigner", UniversalTagNumber.TeletexString));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        ediPartyName.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 1));
        var encoded = writer.Encode();
        var reloaded = new EdiPartyName(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Equal("partyName", reloaded.PartyName);
        Assert.Equal("nameAssigner", reloaded.NameAssigner!);
    }

    [Fact]
    public void CanReloadEdiPartyNameWithoutNameAssigner()
    {
        var ediPartyName = new EdiPartyName(
            new DirectoryString("partyName", UniversalTagNumber.TeletexString));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        ediPartyName.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 1));
        var encoded = writer.Encode();
        var reloaded = new EdiPartyName(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Equal("partyName", reloaded.PartyName);
        Assert.Null(reloaded.NameAssigner);
    }
}
