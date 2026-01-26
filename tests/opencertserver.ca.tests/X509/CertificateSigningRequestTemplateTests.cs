using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509.Templates;
using Xunit;

namespace OpenCertServer.Ca.Tests.X509;

public class CertificateSigningRequestTemplateTests
{
    [Fact]
    public void CanReloadCertificateSigningRequestTemplate()
    {
        var requestTemplate = new CertificateSigningRequestTemplate(
            version: BigInteger.One,
            subject: new NameTemplate(new RDNSequenceTemplate([])),
            subjectPkInfo: new SubjectPublicKeyInfoTemplate(new Oid("1.2.3")));
        var writer = new AsnWriter(AsnEncodingRules.CER);
        requestTemplate.Encode(writer);
        var encoded = writer.Encode();

        var reader = new AsnReader(encoded, AsnEncodingRules.CER);
        var decoded = CertificateSigningRequestTemplate.Read(reader);

        Assert.Equal(requestTemplate.Version, decoded.Version);
        Assert.NotNull(decoded.Subject);
        Assert.NotNull(decoded.SubjectPublicKeyInfo);
    }
}
