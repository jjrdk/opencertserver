using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

namespace OpenCertServer.Ca.Tests.X509;

public class DirectoryStringTests
{
    [Theory]
    [InlineData(UniversalTagNumber.TeletexString)]
    [InlineData(UniversalTagNumber.PrintableString)]
    // TODO: Enable UniversalString test when supported
//    [InlineData(UniversalTagNumber.UniversalString)]
    [InlineData(UniversalTagNumber.UTF8String)]
    [InlineData(UniversalTagNumber.BMPString)]
    public void CanReloadDirectoryString(UniversalTagNumber tagNumber)
    {
        var directoryString = new DirectoryString("testString", tagNumber);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        directoryString.Encode(writer);
        var encoded = writer.Encode();
        var reloaded = new DirectoryString(encoded);

        Assert.Equal("testString", reloaded);
    }
}
