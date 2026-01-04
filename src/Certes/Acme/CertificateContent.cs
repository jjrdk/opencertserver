using System.Security.Cryptography.X509Certificates;

namespace Certes.Acme;

internal class CertificateContent : IEncodable
{
    private readonly X509Certificate2 _cert;

    public CertificateContent(X509Certificate2 pem)
    {
        _cert = pem;
    }

    public byte[] ToDer()
    {
        return _cert.Export(X509ContentType.Cert);
    }

    public string ToPem() => _cert.ExportCertificatePem();
}
