namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Claims;
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
    /// <param name="profile">The CA profile to validate for</param>
    /// <param name="requestor">The user requesting the certificate.</param>
    /// <param name="reenrollingFrom">The optional <see cref="X509Certificate2"/> if re-enrolling.</param>
    /// <param name="cancellationToken">The cancellation token to use for asynchronous operations.</param>
    /// <returns>A <see cref="string"/> with error descriptions, or <c>null</c></returns>
    Task<string?> Validate(
        CertificateRequest request,
        string? profile = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Converts a CSR into the values that should be checked against the authenticated identity.
/// Implementations may read the CSR, the caller identity, and optional profile metadata to decide
/// which values are allowed for the request. Returning null/empty results means the converter does
/// not impose an identity restriction for this request.
/// </summary>
public interface ICertificateRequestValueConverter
{
    /// <summary>
    /// Gets the candidate values embedded in the CSR that should be compared to the authenticated identity.
    /// </summary>
    IReadOnlyCollection<string> GetValues(
        CertificateRequest request,
        string? profile = null,
        ClaimsIdentity? requestor = null);
}
