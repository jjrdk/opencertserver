using System.Formats.Asn1;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils;
using Xunit;

namespace OpenCertServer.Ca.Tests.X509;

public class SubjectPublicKeyInfoTemplateTests
{
    [Fact]
    public void CanReadEcDsaKeyInfo()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var info = key.ExportSubjectPublicKeyInfo();
        var reader = new AsnReader(info, AsnEncodingRules.DER);
        var spki = new Utils.X509.Templates.SubjectPublicKeyInfoTemplate(reader);
        Assert.Equal(Oids.EcPublicKey, spki.AlgorithmOid.Value);
        Assert.Equal(Oids.secp521r1, spki.CurveOid!.Value);
        Assert.NotNull(spki.PublicKey);
    }

    [Fact]
    public void CanReadRsaKeyInfo()
    {
        using var key = RSA.Create(4096);
        var info = key.ExportSubjectPublicKeyInfo();
        var reader = new AsnReader(info, AsnEncodingRules.DER);
        var spki = new Utils.X509.Templates.SubjectPublicKeyInfoTemplate(reader);
        Assert.Equal(Oids.Rsa, spki.AlgorithmOid.Value);
        Assert.Null(spki.CurveOid);
        Assert.NotNull(spki.PublicKey);
    }
}
