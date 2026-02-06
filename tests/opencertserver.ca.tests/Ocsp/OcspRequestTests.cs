namespace OpenCertServer.Ca.Tests.Ocsp;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

public class OcspRequestTests
{
    private const string Base64Request =
        "MFQwUjBQME4wTDAJBgUrDgMCGgUABBQ1uvBCJo3G3TPBvK+GVqszOaLAawQUb38ZjesMwNeYLEzdGvP/Zi9TlkACE3cAEdYaIhMmuymSdxoAAAAR1ho=";

    [Fact]
    public void CanReadOcspRequest()
    {
        var bytes = Convert.FromBase64String(Base64Request);
        var ocspRequest = new OcspRequest(new AsnReader(bytes, AsnEncodingRules.DER));

        Assert.NotNull(ocspRequest);
        Assert.Single(ocspRequest.TbsRequest.RequestList!);
    }

    [Fact]
    public void CanRoundTripRequestSerialization()
    {
        var bytes = Convert.FromBase64String(Base64Request);
        var ocspRequest = new OcspRequest(new AsnReader(bytes, AsnEncodingRules.DER));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        ocspRequest.Encode(writer);
        var encodedBytes = writer.Encode();
        ocspRequest = new OcspRequest(new AsnReader(encodedBytes, AsnEncodingRules.DER));

        Assert.NotNull(ocspRequest);
        Assert.Single(ocspRequest.TbsRequest.RequestList!);
    }

    [Fact]
    public void CanReadOcspRequestWithExtensions()
    {
        var request = new OcspRequest(
            new TbsRequest(TypeVersion.V1,
                new GeneralName(GeneralName.GeneralNameType.X400Address,
                    new AsnString(new Asn1Tag(UniversalTagNumber.UTF8String), "test")),
                [
                    new Request(new CertId(
                        new AlgorithmIdentifier(Oids.Sha256.InitializeOid()),
                        "abc"u8.ToArray(),
                        "abc"u8.ToArray(), "123"u8.ToArray()))
                ]),
            new Signature(new AlgorithmIdentifier(Oids.RsaOid), "signhere"u8.ToArray()));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        request.Encode(writer);
        var encodedBytes = writer.Encode();
        var ocspRequest = new OcspRequest(new AsnReader(encodedBytes, AsnEncodingRules.DER));

        Assert.Equal(TypeVersion.V1, ocspRequest.TbsRequest.Version);
        Assert.Single(ocspRequest.TbsRequest.RequestList);
    }
}
