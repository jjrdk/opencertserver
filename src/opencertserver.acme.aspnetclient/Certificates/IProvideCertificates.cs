namespace OpenCertServer.Acme.AspNetClient.Certificates;

using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

public interface IProvideCertificates
{
    Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        CancellationToken cancellationToken = default);

    Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        X509Certificate2? current,
        CancellationToken cancellationToken = default);

    Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        string? routeId,
        X509Certificate2? current = null,
        CancellationToken cancellationToken = default);

    Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        string? routeId,
        IReadOnlyList<string> hosts,
        X509Certificate2? current = null,
        CancellationToken cancellationToken = default);
}
