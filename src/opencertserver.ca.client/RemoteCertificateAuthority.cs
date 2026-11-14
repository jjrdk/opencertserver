namespace OpenCertServer.Ca.Client;

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// An <see cref="ICertificateAuthority"/> that delegates every operation to a backing CA over a trusted
/// HTTPS connection. This lets an ACME server or an RA run as its own process: ACME's
/// <c>DefaultRevocationService</c> and a remote issuer both consume <see cref="ICertificateAuthority"/>
/// unchanged, so swapping the in-process authority for this one is a pure wiring change.
/// </summary>
public sealed class RemoteCertificateAuthority : ICertificateAuthority
{
    private readonly CaClient _client;
    private readonly X509Certificate2? _revokeIdentity;
    private bool _disposed;

    /// <summary>
    /// Creates a remote authority backed by <paramref name="client"/>. The optional
    /// <paramref name="revokeIdentity"/> is a certificate with its private key, used to sign the
    /// revocation proof-of-possession; it may be null when revocation is not used by this process.
    /// </summary>
    public RemoteCertificateAuthority(CaClient client, X509Certificate2? revokeIdentity = null)
    {
        _client = client;
        _revokeIdentity = revokeIdentity;
    }

    /// <inheritdoc />
    public Task<SignCertificateResponse> SignCertificateRequest(
        CertificateRequest request,
        string? profileName = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return SignCertificateRequestPem(request.ToPkcs10Pem(), profileName, requestor, reenrollingFrom,
            notBefore, notAfter, cancellationToken);
    }

    /// <inheritdoc />
    public Task<SignCertificateResponse> SignCertificateRequestPem(
        string request,
        string? profileName = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null,
        CancellationToken cancellationToken = default)
    {
        // The requestor identity is not forwarded as a separate claim: the backing CA authenticates this
        // process over the trusted connection (mTLS or bearer), and that principal is the RA identity
        // the CA already trusts. The delegated scope, when any, comes from the client configuration.
        // The certificate being re-enrolled from, however, must cross the wire so the CA can
        // supersede-revoke it on the new one: a remote SCEP renewal or EST re-enrollment therefore
        // carries <paramref name="reenrollingFrom"/> as the X-Reenrolling-From header.
        return _client.SignCsr(request, profileName, null, reenrollingFrom, notBefore, notAfter, cancellationToken);
    }

    /// <inheritdoc />
    public Task<X509Certificate2Collection> GetRootCertificates(
        string? profileName = null,
        CancellationToken cancellationToken = default)
    {
        return _client.GetRootCertificates(profileName, cancellationToken);
    }

    /// <inheritdoc />
    public Task<X509Certificate2Collection> GetPublishedCertificates(
        string? profileName = null,
        CancellationToken cancellationToken = default)
    {
        // The full published chain (issuing CA plus root and any published intermediates) is fetched
        // from the CA's published endpoint so a SCEP/EST peer gets exactly what the CA publishes, not
        // just the root anchor.
        return _client.GetPublishedCertificates(profileName, cancellationToken);
    }

    public async Task<IReadOnlyList<string>> GetSupportedProfiles(CancellationToken cancellationToken = default)
    {
        return await _client.GetProfiles(cancellationToken);
    }

    /// <inheritdoc />
    public Task<bool> RevokeCertificate(
        string serialNumber,
        string? profileName,
        X509RevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        if (_revokeIdentity is null)
        {
            return Task.FromException<bool>(new NotSupportedException(
                "Remote revocation requires a revoking identity with a private key to sign the " +
                "proof-of-possession message. Configure a client certificate with a private key."));
        }

        return _client.Revoke(_revokeIdentity, serialNumber, profileName, reason, cancellationToken);
    }

    /// <inheritdoc />
    public Task<byte[]> GetRevocationList(
        string? profileName = null,
        CancellationToken cancellationToken = default)
    {
        return _client.GetRevocationList(profileName, cancellationToken);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _revokeIdentity?.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
