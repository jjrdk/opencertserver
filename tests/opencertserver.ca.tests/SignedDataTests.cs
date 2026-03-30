namespace OpenCertServer.Ca.Tests;

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Pkcs7;
using Xunit;

public class SignedDataTests
{
    [Fact]
    public void CanRoundTripCertOnlySignedData()
    {
        var key = RSA.Create(2048);
        var csr = new CertificateRequest(new X500DistinguishedName("CN=Test"), key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var cert = csr.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
        var signedData = new SignedData(
            version: 4,
            certificates: [cert]);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        signedData.Encode(writer);
        var bytes = writer.Encode();

        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        var decodedSignedData = new SignedData(reader);
        Assert.Equal(signedData.Certificates?.Length, decodedSignedData.Certificates?.Length);
    }
}
