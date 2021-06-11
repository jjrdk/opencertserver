namespace OpenCertServer.Ca
{
    using System;
    using System.Security.Cryptography.X509Certificates;

    public interface ICertificateAuthority : IDisposable
    {
        SignCertificateResponse SignCertificateRequest(CertificateRequest request, X509Certificate2? reenrollingFrom = null);

        SignCertificateResponse SignCertificateRequest(string request);

        SignCertificateResponse SignCertificateRequest(byte[] bytes);
    }
}