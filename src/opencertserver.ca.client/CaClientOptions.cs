using Microsoft.Extensions.Configuration;

namespace OpenCertServer.Ca.Client;

/// <summary>
/// Configuration for the outbound HTTP client that talks to a backing certificate authority.
/// The values are read by hand (no <c>Bind</c>) so the client stays AOT-safe and can run in the
/// trimmable ACME/RA host.
/// </summary>
public sealed class CaClientOptions
{
    /// <summary>Gets the backing CA base address. Only absolute HTTPS endpoints are accepted.</summary>
    public required Uri BaseUrl { get; init; }

    /// <summary>Gets the CA profile to use, or null to use the CA's default profile.</summary>
    public string? Profile { get; init; }

    /// <summary>
    /// Gets the set of profiles this client is delegated to, or empty to be allowed to use every
    /// profile the backing CA supports. A non-empty set restricts the client to that subset. The set
    /// may be refreshed from the CA at runtime via <see cref="CaClient.GetProfiles"/>.
    /// </summary>
    public IReadOnlyList<string> Profiles { get; init; } = Array.Empty<string>();

    /// <summary>Gets the delegated DNS suffix sent as the <c>X-Delegated-Subject</c> header, if any.</summary>
    public string? DelegatedScope { get; init; }

    /// <summary>Gets the optional bearer token used to authenticate to the backing CA.</summary>
    public string? BearerToken { get; init; }

    /// <summary>
    /// Gets the path to the trust anchor (PEM or PFX) pinned into the outbound TLS handler, or null to
    /// use the default system trust. Pinning the backing CA's chain is how the "trusted connection" is
    /// enforced end-to-end.
    /// </summary>
    public string? TrustCertPath { get; init; }

    /// <summary>
    /// Gets the path to the client certificate (PFX with private key) presented for mTLS, or null to
    /// authenticate with a bearer token or anonymously.
    /// </summary>
    public string? ClientCertPath { get; init; }

    /// <summary>Gets the PFX password for the client certificate, if required.</summary>
    public string? ClientCertPassword { get; init; }

    /// <summary>Gets the path used to fetch root certificates, relative to <see cref="BaseUrl"/>.</summary>
    public string RootsPath { get; init; } = "cacerts";

    /// <summary>Gets the path used to fetch the revocation list, relative to <see cref="BaseUrl"/>.</summary>
    public string RevocationListPath { get; init; } = "ca/crl";

    /// <summary>
    /// Reads backing-CA client settings from the <c>Ca</c> configuration section and rejects non-HTTPS
    /// or incomplete configuration. This is the config surface for <c>AcmeServer:Issuer=remote</c>.
    /// </summary>
    public static CaClientOptions FromConfiguration(IConfiguration configuration)
    {
        var section = configuration.GetSection("Ca");
        var baseAddress = section["RemoteUrl"] ?? section["BaseUrl"];
        if (!Uri.TryCreate(baseAddress, UriKind.Absolute, out var baseUrl) ||
            !string.Equals(baseUrl.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Ca:RemoteUrl must be an absolute HTTPS URL.");
        }

        baseUrl = baseUrl.AbsoluteUri.EndsWith("/", StringComparison.Ordinal)
            ? baseUrl
            : new Uri(baseUrl.AbsoluteUri + "/", UriKind.Absolute);

        return new CaClientOptions
        {
            BaseUrl = baseUrl,
            Profile = section["Profile"],
            Profiles = ParseProfiles(section["Profiles"]),
            DelegatedScope = section["DelegatedScope"],
            BearerToken = section["BearerToken"],
            TrustCertPath = section["Trust"],
            ClientCertPath = section["ClientCert"],
            ClientCertPassword = section["ClientCertPassword"],
            RootsPath = section["RootsPath"] ?? "cacerts",
            RevocationListPath = section["RevocationListPath"] ?? "ca/crl",
        };
    }

    /// <summary>
    /// Configures an outbound <see cref="HttpClientHandler"/> to pin the trust anchor and present the
    /// mTLS client certificate. Used by the DI extension so the handler carries the same pinning the
    /// options describe.
    /// </summary>
    public void ConfigureHandler(HttpClientHandler handler)
    {
        if (!string.IsNullOrWhiteSpace(TrustCertPath))
        {
            var pinned = new System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            {
                System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(
                    System.IO.File.ReadAllBytes(TrustCertPath)),
            };
            handler.ServerCertificateCustomValidationCallback =
                (_, presented, _, _) => ChainIsValidAgainst(pinned, presented);
        }

        if (!string.IsNullOrWhiteSpace(ClientCertPath))
        {
            var client = System.Security.Cryptography.X509Certificates.X509CertificateLoader
                .LoadPkcs12(System.IO.File.ReadAllBytes(ClientCertPath),
                    string.IsNullOrEmpty(ClientCertPassword) ? string.Empty : ClientCertPassword);
            handler.ClientCertificates.Add(client);
        }
    }

    /// <summary>
    /// Parses a comma-separated profile list from configuration into the delegated profile set; a blank
    /// value yields an empty set, which means "all profiles the CA supports".
    /// </summary>
    private static IReadOnlyList<string> ParseProfiles(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Array.Empty<string>();
        }

        return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    /// <summary>
    /// Accepts a presented server certificate only when it chains to one of the pinned anchors. This
    /// is the fail-closed "trusted connection" check: a non-matching chain is rejected even if the
    /// system store would otherwise trust it.
    /// </summary>
    private static bool ChainIsValidAgainst(
        System.Security.Cryptography.X509Certificates.X509Certificate2Collection pinned,
        System.Security.Cryptography.X509Certificates.X509Certificate2? presented)
    {
        if (presented is null)
        {
            return false;
        }

        var chain = new System.Security.Cryptography.X509Certificates.X509Chain
        {
            ChainPolicy = new System.Security.Cryptography.X509Certificates.X509ChainPolicy
            {
                RevocationFlag = System.Security.Cryptography.X509Certificates.X509RevocationFlag.ExcludeRoot,
                RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
            },
        };
        chain.Build(presented);

        var anchors = pinned
            .Select(p => p.Thumbprint)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return chain.ChainElements.Any(element => anchors.Contains(element.Certificate.Thumbprint));
    }
}
