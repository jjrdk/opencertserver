namespace OpenCertServer.Ca.Utils.X509Extensions.Templates;

using System.Formats.Asn1;
using System.Numerics;

public class CertificateSigningRequestTemplate
{
    public CertificateSigningRequestTemplate(
        BigInteger version,
        X500DistinguishedNameTemplate? name,
        SubjectPublicKeyInfoTemplate? subjectPublicKeyInfoTemplate = null)
    {
        Version = version;
        Name = name;
        PublicKey = subjectPublicKeyInfoTemplate;
    }

    public BigInteger Version { get; }

    public X500DistinguishedNameTemplate? Name { get; }
    public SubjectPublicKeyInfoTemplate? PublicKey { get; }

    public static CertificateSigningRequestTemplate Read(AsnReader reader)
    {
        var version = reader.ReadInteger();
        var name = new X500DistinguishedNameTemplate([]);

        return new CertificateSigningRequestTemplate(version, name);
    }
}
