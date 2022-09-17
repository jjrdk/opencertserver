namespace OpenCertServer.Acme.AspNetClient.Certificates
{
    using System.Security.Cryptography.X509Certificates;

    public sealed class CertificateRenewalResult
    {
        public CertificateRenewalResult(X509Certificate2? certificate, CertificateRenewalStatus status)
        {
            Certificate = certificate;
            Status = status;
        }

        public X509Certificate2? Certificate { get; }
        
        public CertificateRenewalStatus Status { get; }
    }
}