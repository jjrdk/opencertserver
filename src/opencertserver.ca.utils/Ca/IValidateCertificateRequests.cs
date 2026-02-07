namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Defines the interface for validating certificate requests.
/// </summary>
public interface IValidateCertificateRequests
{
    /// <summary>
    /// Validates the given <see cref="CertificateRequest"/>.
    /// </summary>
    /// <param name="request">The request to validate.</param>
    /// <param name="reenrollingFrom">The optional <see cref="X509Certificate2"/> if re-enrolling.</param>
    /// <returns>A <see cref="string"/> with error descriptions, or <c>null</c></returns>
    string? Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null);
}
