namespace OpenCertServer.Acme.AspNetClient.Certificates
{
    using System.Threading.Tasks;

    public interface ICertificateProvider
    {
        Task<CertificateRenewalResult> RenewCertificateIfNeeded(IAbstractCertificate? current = null);
    }
}