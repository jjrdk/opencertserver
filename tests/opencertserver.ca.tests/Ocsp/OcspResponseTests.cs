namespace OpenCertServer.Ca.Tests.Ocsp;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Utils;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Ca.Utils.X509;
using Xunit;

public class OcspResponseTests
{
    [Fact]
    public void CanRoundtripOcspResponse()
    {
        var response = new OcspResponse(
            OcspResponseStatus.Successful,
            new OcspBasicResponse(
                new ResponseData(
                    TypeVersion.V1,
                    new ResponderIdByKey("keyhash"u8.ToArray()),
                    DateTimeOffset.UtcNow,
                    [
                        new SingleResponse(
                            new CertId(
                                new AlgorithmIdentifier(Oids.Sha256.InitializeOid()),
                                "abc"u8.ToArray(),
                                "abc"u8.ToArray(), "123"u8.ToArray()),
                            (CertificateStatus.Revoked,
                             new RevokedInfo(DateTimeOffset.UtcNow, X509RevocationReason.CessationOfOperation)),
                            DateTimeOffset.UtcNow,
                            DateTimeOffset.UtcNow.AddDays(1))
                    ]),
                new AlgorithmIdentifier(Oids.Rsa.InitializeOid()), "signhere"u8.ToArray()));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        response.Encode(writer);
        var encodedBytes = writer.Encode();
        var ocspResponse = new OcspResponse(new AsnReader(encodedBytes, AsnEncodingRules.DER));

        Assert.Equal(OcspResponseStatus.Successful, ocspResponse.ResponseStatus);
        Assert.NotNull(ocspResponse.ResponseBytes);
        Assert.NotNull(new OcspBasicResponse(new AsnReader(ocspResponse.ResponseBytes.Response, AsnEncodingRules.DER)));
    }
    // A signature covers the DER of tbsResponseData as signed. Decoding and re-encoding is not
    // byte-exact: .NET reads some fractional GeneralizedTime values one tick low (.043 becomes
    // .0429999, .5174610 becomes .5174609; dotnet/runtime#134839, ASN1-GENTIME-1), so the bytes
    // have to be kept as received.
    [Theory]
    [InlineData(430_000L)]
    [InlineData(5_174_610L)]
    public void TbsResponseDataBytesAreTheBytesAsReceived(long fractionTicks)
    {
        var time = new DateTimeOffset(2026, 10, 11, 19, 46, 44, TimeSpan.Zero).AddTicks(fractionTicks);
        var original = new OcspBasicResponse(
            new ResponseData(
                TypeVersion.V1,
                new ResponderIdByKey("keyhash"u8.ToArray()),
                time,
                [
                    new SingleResponse(
                        new CertId(
                            new AlgorithmIdentifier(Oids.Sha256.InitializeOid()),
                            "abc"u8.ToArray(),
                            "abc"u8.ToArray(), "123"u8.ToArray()),
                        (CertificateStatus.Good, null),
                        time,
                        time.AddHours(1))
                ]),
            new AlgorithmIdentifier(Oids.Rsa.InitializeOid()), "signhere"u8.ToArray());
        var writer = new AsnWriter(AsnEncodingRules.DER);
        original.Encode(writer);

        var read = new OcspBasicResponse(new AsnReader(writer.Encode(), AsnEncodingRules.DER));

        Assert.Equal(original.TbsResponseDataBytes, read.TbsResponseDataBytes);
    }
}
