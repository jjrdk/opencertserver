namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Defines the ICertificateAuthority interface.
/// </summary>
/// <summary>
/// Represents the ICertificateAuthority.
/// </summary>
public interface ICertificateAuthority
{
    /// <summary>
    /// Signs a certificate request.
    /// </summary>
    /// <param name="request">The certificate request to sign.</param>
    /// <param name="profileName">The name of the profile to use for signing the request.</param>
    /// <param name="requestor">The identity of the requestor.</param>
    /// <param name="reenrollingFrom">The certificate to reenroll from, if applicable.</param>
    /// <param name="cancellationToken">The cancellation token to use for the operation.</param>
    /// <returns>The response containing the signed certificate.</returns>
    Task<SignCertificateResponse> SignCertificateRequest(
        CertificateRequest request,
        string? profileName = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs a certificate request using PEM format.
    /// </summary>
    /// <param name="request">The PEM-encoded certificate request.</param>
    /// <param name="profileName">The name of the profile to use for signing the request.</param>
    /// <param name="requestor">The identity of the requestor.</param>
    /// <param name="reenrollingFrom">The certificate to reenroll from, if applicable.</param>
    /// <param name="cancellationToken">The cancellation token to use for the operation.</param>
    /// <returns>The response containing the signed certificate.</returns>
    Task<SignCertificateResponse> SignCertificateRequestPem(
        string request,
        string? profileName = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the root certificates for the specified profile.
    /// </summary>
    /// <param name="profileName">The name of the profile to get the root certificates for.</param>
    /// <param name="cancellationToken">The cancellation token to use for the operation.</param>
    /// <returns>The root certificates as a collection of X509Certificate2 objects.</returns>
    Task<X509Certificate2Collection> GetRootCertificates(string? profileName = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a certificate by its serial number.
    /// </summary>
    /// <param name="serialNumber">The serial number of the certificate to revoke.</param>
    /// <param name="reason">The reason for revoking the certificate.</param>
    /// <param name="cancellationToken">The cancellation token to use for the operation.</param>
    /// <returns>True if the certificate was successfully revoked, false otherwise.</returns>
    Task<bool> RevokeCertificate(string serialNumber, X509RevocationReason reason, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the revocation list for the specified profile.
    /// </summary>
    /// <param name="profileName">The name of the profile to get the revocation list for.</param>
    /// <param name="cancellationToken">The cancellation token to use for the operation.</param>
    /// <returns>The revocation list as a byte array.</returns>
    Task<byte[]> GetRevocationList(string? profileName = null, CancellationToken cancellationToken = default);
}
