namespace OpenCertServer.Ca.Tests.X509;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

public class DistributionPointTests
{
    [Fact]
    public void CanReloadDistributionPointWithReasons()
    {
        var distributionPoint = new DistributionPoint(reasons: X509RevocationReason.KeyCompromise);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        distributionPoint.Encode(writer, null);
        var encoded = writer.Encode();
        var reloaded = new DistributionPoint(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Equal(X509RevocationReason.KeyCompromise, reloaded.Reasons);
        Assert.Null(reloaded.CrlIssuer);
        Assert.Null(reloaded.DistributionPointName);
    }

    [Fact]
    public void CanReloadDistributionPointWithCrlIssuer()
    {
        var distributionPoint = new DistributionPoint(crlIssuer: new GeneralNames(
            new GeneralName(GeneralName.GeneralNameType.DnsName,
                new AsnString(new Asn1Tag(UniversalTagNumber.UTF8String), "hello"))));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        distributionPoint.Encode(writer, null);
        var encoded = writer.Encode();
        var reloaded = new DistributionPoint(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Null(reloaded.Reasons);
        Assert.Equal("hello", reloaded.CrlIssuer!.Names[0].Value.ToString());
        Assert.Null(reloaded.DistributionPointName);
    }

    [Fact]
    public void CanReloadDistributionPointWithDistributionPointName()
    {
        var distributionPoint = new DistributionPoint(
            distributionPointName: new DistributionPointName(DistributionPointName.DistributionPointNameType.FullName,
                new GeneralNames(
                    new GeneralName(GeneralName.GeneralNameType.DnsName,
                        new AsnString(new Asn1Tag(UniversalTagNumber.UTF8String), "hello")))));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        distributionPoint.Encode(writer, null);
        var encoded = writer.Encode();
        var reloaded = new DistributionPoint(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Null(reloaded.Reasons);
        Assert.Null(reloaded.CrlIssuer);
        Assert.Equal("hello", reloaded.DistributionPointName?.FullName?.Names[0].Value.ToString());
    }

    [Fact]
    public void CanReloadDistributionPointWithAllFields()
    {
        var distributionPoint = new DistributionPoint(
            distributionPointName: new DistributionPointName(DistributionPointName.DistributionPointNameType.FullName,
                new GeneralNames(
                    new GeneralName(GeneralName.GeneralNameType.DnsName,
                        new AsnString(new Asn1Tag(UniversalTagNumber.UTF8String), "hello")))),
            reasons: X509RevocationReason.KeyCompromise,
            crlIssuer: new GeneralNames(
                new GeneralName(GeneralName.GeneralNameType.DnsName,
                    new AsnString(new Asn1Tag(UniversalTagNumber.UTF8String), "world"))));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        distributionPoint.Encode(writer, null);
        var encoded = writer.Encode();
        var reloaded = new DistributionPoint(new AsnReader(encoded, AsnEncodingRules.DER));

        Assert.Equal(X509RevocationReason.KeyCompromise, reloaded.Reasons);
        Assert.Equal("world", reloaded.CrlIssuer!.Names[0].Value.ToString());
        Assert.Equal("hello", reloaded.DistributionPointName?.FullName?.Names[0].Value.ToString());
    }
}
