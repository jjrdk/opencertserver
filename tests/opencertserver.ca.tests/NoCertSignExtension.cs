using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Ca.Tests;

internal class NoCertSignExtension : IValidateCertificateRequests
{
    public Task<string?> Validate(
        CertificateRequest request,
        string? profile = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        CancellationToken cancellationToken = default)
    {
        var result = request.CertificateExtensions.OfType<X509KeyUsageExtension>()
            .Any(ext => (ext.KeyUsages & X509KeyUsageFlags.KeyCertSign) != 0)
            ? "Certificate signing is not allowed."
            : null;
        return Task.FromResult(result);
    }
}
