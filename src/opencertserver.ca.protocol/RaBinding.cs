namespace OpenCertServer.Ca.Protocol;

/// <summary>
/// Defines the profiles and DNS scopes an authenticated registration authority may act for.
/// A scope is a DNS suffix such as <c>tenant-a.example.com</c>.
/// </summary>
/// <remarks>
/// Lives in the shared protocol package so a registration authority and the certificate authority
/// that authorizes it use one and the same definition.
/// </remarks>
public sealed record RaBinding(
    string RaId,
    IReadOnlySet<string> AllowedScopes,
    IReadOnlySet<string> AllowedProfiles)
{
    /// <summary>Gets the SHA-256 certificate fingerprints permitted to authenticate this RA over mTLS.</summary>
    public IReadOnlySet<string> CertificateSha256Thumbprints { get; init; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Stores the registration-authority bindings accepted by a certificate authority.
/// </summary>
public interface IStoreRas
{
    /// <summary>
    /// Finds an RA binding by its authenticated identity.
    /// </summary>
    Task<RaBinding?> Find(string raId, CancellationToken cancellationToken = default);
}

/// <summary>
/// In-memory registration-authority binding store for configuration-backed deployments.
/// </summary>
public sealed class InMemoryRaStore : IStoreRas
{
    private readonly IReadOnlyDictionary<string, RaBinding> _bindings;

    /// <summary>
    /// Initializes a binding store.
    /// </summary>
    public InMemoryRaStore(IEnumerable<RaBinding>? bindings = null)
    {
        _bindings = (bindings ?? [])
            .ToDictionary(binding => binding.RaId, StringComparer.Ordinal);
    }

    /// <inheritdoc />
    public Task<RaBinding?> Find(string raId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _bindings.TryGetValue(raId, out var binding);
        return Task.FromResult(binding);
    }
}

/// <summary>
/// Claim and HTTP header names used to identify an RA and its delegated DNS scope.
/// The RA identity claim must come from the configured authentication provider; the scope header
/// is only a request selector and is checked against the stored binding. The values are aliases of
/// the <see cref="RaProtocol"/> constants so both the RA and the CA sides read the same source.
/// </summary>
public static class RaClaimTypes
{
    /// <summary>The authenticated registration-authority identifier claim.</summary>
    public const string RaId = RaProtocol.RaIdClaim;

    /// <summary>The requested delegated DNS scope claim.</summary>
    public const string DelegatedSubject = RaProtocol.DelegatedSubjectClaim;

    /// <summary>The HTTP header used by an RA client to select a delegated DNS scope.</summary>
    public const string DelegatedSubjectHeader = RaProtocol.DelegatedSubjectHeader;
}
