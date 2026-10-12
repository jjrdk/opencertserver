namespace OpenCertServer.Acme.Server.Configuration;

public sealed class AcmeServerOptions
{
    public BackgroundServiceOptions HostedWorkers { get; set; } = new();

    public string? WebsiteUrl { get; set; }

    public TimeSpan UrlRetrievalTimeout { get; set; } = TimeSpan.FromSeconds(100);

    public bool ExternalAccountRequired { get; set; }

    public TOSOptions TOS { get; set; } = new();

    /// <summary>
    /// Gets or sets the CAA identities that are served in the ACME directory.
    /// When non-empty, the CA validates inbound ACME orders against the CAA RRset
    /// published in DNS and only issues when the RRset authorizes at least one of
    /// these identities.  When empty (the default), CAA checks are enforced by
    /// refusing issuance unless <see cref="DisableCaaChecks"/> is explicitly set.
    /// </summary>
    public string[]? CAAIdentities { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether CAA DNS checks are disabled.
    /// Set this to <see langword="true"/> only in controlled environments where
    /// CAA enforcement is inappropriate (e.g. isolated lab deployments or
    /// internal-only CAs with no public DNS).  When <see langword="false"/>
    /// (the default) and <see cref="CAAIdentities"/> is empty or null, the
    /// validator rejects every order with a configuration-error response to
    /// prevent silent mis-issuance.
    /// </summary>
    public bool DisableCaaChecks { get; set; }
}
