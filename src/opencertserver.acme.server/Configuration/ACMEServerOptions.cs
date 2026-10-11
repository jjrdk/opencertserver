namespace OpenCertServer.Acme.Server.Configuration;

using DnsClientX;

public sealed class AcmeServerOptions
{
    public BackgroundServiceOptions HostedWorkers { get; set; } = new();

    public string? WebsiteUrl { get; set; }

    public bool ExternalAccountRequired { get; set; }

    public TOSOptions TOS { get; set; } = new();

    /// <summary>
    /// Gets or sets the CAA identities that are served in the ACME directory.
    /// </summary>
    public string[]? CAAIdentities { get; set; }

    /// <summary>
    /// Gets or sets the DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) endpoint used for
    /// all issuance-critical DNS lookups (CAA records, http-01 IP validation, dns-01 TXT records).
    /// Defaults to <see cref="DnsEndpoint.Cloudflare"/> to avoid dependence on the ambient
    /// system resolver, which may be poisoned, rebinding-capable, or misconfigured.
    /// </summary>
    public DnsEndpoint DnsEndpoint { get; set; } = DnsEndpoint.Cloudflare;
}
