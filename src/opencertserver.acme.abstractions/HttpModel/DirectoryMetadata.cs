namespace OpenCertServer.Acme.Abstractions.HttpModel;

/// <summary>
/// Describes the HTTP-Response-Model for ACME DirectoryMetadata.
/// See RFC 8555, section 7.1.1.
/// </summary>
public sealed class DirectoryMetadata
{
    /// <summary>
    /// Gets or sets the terms of service URL, if present.
    /// </summary>
    public string? TermsOfService { get; set; }
    /// <summary>
    /// Gets or sets the website URL, if present.
    /// </summary>
    public string? Website { get; set; }
    /// <summary>
    /// Gets or sets the CAA identities string, if present.
    /// </summary>
    public string? CAAIdentities { get; set; }
    /// <summary>
    /// Gets or sets a value indicating whether external account binding is required.
    /// </summary>
    public bool? ExternalAccountRequired { get; set; }
}
