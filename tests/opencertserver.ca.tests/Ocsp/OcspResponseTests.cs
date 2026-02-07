namespace OpenCertServer.Ca.Tests.Ocsp;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
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
}
