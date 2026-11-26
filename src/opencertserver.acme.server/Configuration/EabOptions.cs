namespace OpenCertServer.Acme.Server.Configuration;

using System.Collections.Generic;

/// <summary>Configuration for ACME External Account Binding.</summary>
public sealed class EabOptions
{
    /// <summary>
    /// Gets or sets whether EAB is enabled. Defaults to true to preserve existing
    /// deployments that provision keys through <c>AcmeServer:ExternalAccountKey</c>.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Gets provisioned EAB accounts keyed by their external account key identifier.</summary>
    public Dictionary<string, EabAccountOptions> Accounts { get; set; } = new();
}

/// <summary>Configuration for a single provisioned external account key.</summary>
public sealed class EabAccountOptions
{
    /// <summary>Gets or sets the base64url-encoded HMAC key.</summary>
    public string? MacKey { get; set; }

    /// <summary>Gets or sets the HMAC algorithm. Defaults to HS256.</summary>
    public string MacAlgorithm { get; set; } = "HS256";
}
