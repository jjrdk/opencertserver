namespace OpenCertServer.Contrib.Intune;

/// <summary>
/// How to reach Intune and Microsoft Graph. Bound from configuration under
/// <c>Scep:Intune</c> (environment: <c>Scep__Intune__ClientSecret</c> and so on);
/// the secret may also come from a file (<see cref="ClientSecretFile"/>) so it
/// stays out of the process environment.
/// </summary>
public sealed class IntuneOptions
{
    public const string SectionName = "Scep:Intune";

    /// <summary>The Entra tenant (GUID or domain) that owns the Intune instance.</summary>
    public required string TenantId { get; init; }

    /// <summary>The app registration with <c>scep_challenge_provider</c> (Intune) and the Graph permissions for the sync.</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The app's certificate (PEM) for a signed client assertion - the credential Microsoft
    /// recommends over a secret: only the public half goes to Entra. Set together with
    /// <see cref="ClientCertificateKeyFile"/>; a secret is then not needed.
    /// </summary>
    public string? ClientCertificateFile { get; init; }

    /// <summary>The private key (PEM, RSA) belonging to <see cref="ClientCertificateFile"/>.</summary>
    public string? ClientCertificateKeyFile { get; init; }

    /// <summary>The client secret - or leave empty and set <see cref="ClientSecretFile"/> or a certificate.</summary>
    public string? ClientSecret { get; init; }

    /// <summary>A file holding the client secret (first line), read once at startup.</summary>
    public string? ClientSecretFile { get; init; }

    /// <summary>Sent as <c>callerInfo</c> to Intune; shows up in its logs.</summary>
    public string CallerInfo { get; init; } = "OpenCertServer";

    /// <summary>Login endpoint; override for national clouds.</summary>
    public Uri LoginBase { get; init; } = new("https://login.microsoftonline.com/");

    /// <summary>Microsoft Graph; override for national clouds (and for tests).</summary>
    public Uri GraphBase { get; init; } = new("https://graph.microsoft.com/");

    /// <summary>The Intune resource the token is requested for; override for national clouds.</summary>
    public Uri IntuneResource { get; init; } = new("https://api.manage.microsoft.com/");

    /// <summary>
    /// Fixed address of the SCEP validation service. Normally discovered through Graph
    /// (service principal <c>0000000a-0000-0000-c000-000000000000</c>); set for tests
    /// or when discovery is not available.
    /// </summary>
    public Uri? ValidationEndpoint { get; init; }

    /// <summary>How long a request to Intune or Graph may take before it counts as unreachable.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The revocation sync aborts when it would revoke more than this many certificates
    /// in one run - a guard against a misconfigured tenant or permission revoking everyone.
    /// </summary>
    public int MaxRevocationsPerSync { get; init; } = 25;

    internal bool UsesCertificate => !string.IsNullOrEmpty(ClientCertificateFile);

    internal string? ResolveClientSecret()
    {
        if (UsesCertificate)
        {
            return null;
        }

        if (!string.IsNullOrEmpty(ClientSecret))
        {
            return ClientSecret;
        }

        if (!string.IsNullOrEmpty(ClientSecretFile))
        {
            var line = File.ReadLines(ClientSecretFile).FirstOrDefault()?.Trim();
            if (!string.IsNullOrEmpty(line))
            {
                return line;
            }

            throw new InvalidOperationException($"The Intune client secret file {ClientSecretFile} is empty.");
        }

        throw new InvalidOperationException(
            "Scep:Intune needs a credential: ClientCertificateFile with ClientCertificateKeyFile, or ClientSecret / ClientSecretFile.");
    }
}
