namespace OpenCertServer.Acme.Abstractions.HttpModel;

/// <summary>
/// Describes the HTTP-Response-Model for an ACME Directory.
/// See RFC 8555, section 7.1.1.
/// </summary>
public sealed class Directory
{
    /// <summary>
    /// Gets or sets the URL for requesting a new nonce.
    /// </summary>
    public string? NewNonce { get; set; }
    /// <summary>
    /// Gets or sets the URL for creating a new account.
    /// </summary>
    public string? NewAccount { get; set; }
    /// <summary>
    /// Gets or sets the URL for creating a new order.
    /// </summary>
    public string? NewOrder { get; set; }
    /// <summary>
    /// Gets or sets the URL for creating a new authorization (optional, legacy).
    /// </summary>
    public string? NewAuthz { get; set; }
    /// <summary>
    /// Gets or sets the URL for revoking a certificate.
    /// </summary>
    public string? RevokeCert { get; set; }
    /// <summary>
    /// Gets or sets the URL for key rollover/change.
    /// </summary>
    public string? KeyChange { get; set; }
    /// <summary>
    /// Gets or sets the directory metadata object, if present.
    /// </summary>
    public DirectoryMetadata? Meta { get; set; }
}
