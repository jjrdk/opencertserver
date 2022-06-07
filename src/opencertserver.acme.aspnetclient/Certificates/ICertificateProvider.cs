namespace OpenCertServer.Acme.AspNetClient.Certificates
{
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    public interface ICertificateProvider
    {
        Task<CertificateRenewalResult> RenewCertificateIfNeeded(string password, X509Certificate2? current = null);
    }
}