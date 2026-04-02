namespace OpenCertServer.Est.Client;

using System.Security.Cryptography.X509Certificates;

public enum EstTrustAnchorMode
{
    ImplicitOnly = 1,
    ExplicitOnly = 2,
    ExplicitThenImplicit = ExplicitOnly | ImplicitOnly
}

public sealed class EstClientOptions
{
    public EstTrustAnchorMode TrustAnchorMode { get; init; } = EstTrustAnchorMode.ImplicitOnly;

    // Explicit trust anchors per RFC 7030 Section 3.1
    public X509Certificate2Collection ExplicitTrustAnchors { get; } = [];

    // Later for RFC 6125 / redirect handling
    public Uri? AuthorizedUri { get; init; }

    // Useful operational knobs
    public X509RevocationMode RevocationMode { get; init; } = X509RevocationMode.NoCheck;
    public X509RevocationFlag RevocationFlag { get; init; } = X509RevocationFlag.ExcludeRoot;

    // Future EST bootstrap support
    public bool AllowBootstrapCaCertsWithoutTrustedServer { get; init; } = false;
}
