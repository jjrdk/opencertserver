namespace OpenCertServer.Ca.Tests.X509;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509.Templates;
using Xunit;

public class CertificateSigningRequestTemplateTests
{
    [Fact]
    public void CanReloadCertificateSigningRequestTemplate()
    {
        var requestTemplate = new CertificateSigningRequestTemplate(
            subject: new NameTemplate(new RDNSequenceTemplate([
                new RelativeDistinguishedNameTemplate([new SingleAttributeTemplate(Oids.CommonNameOid)])
            ])),
            subjectPkInfo: new SubjectPublicKeyInfoTemplate(Oids.RsaOid));
        var writer = new AsnWriter(AsnEncodingRules.CER);
        requestTemplate.Encode(writer);
        var encoded = writer.Encode();

        var reader = new AsnReader(encoded, AsnEncodingRules.CER);
        var decoded = new CertificateSigningRequestTemplate(reader);

        Assert.Equal(requestTemplate.Version, decoded.Version);
        Assert.Equal(Oids.CommonNameOid, decoded.Subject!.Name.RelativeNames[0].Attributes.First().Oid, OidComparer.Instance);
        Assert.Equal(Oids.RsaOid,decoded.SubjectPublicKeyInfo!.AlgorithmOid, OidComparer.Instance);
    }
}
