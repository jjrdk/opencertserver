using System.Text.Json.Serialization;
using CertesSlim.Acme.Resource;

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
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NewNonce { get; set; }

    /// <summary>
    /// Gets or sets the URL for creating a new account.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NewAccount { get; set; }

    /// <summary>
    /// Gets or sets the URL for creating a new order.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NewOrder { get; set; }

    /// <summary>
    /// Gets or sets the URL for creating a new authorization (optional, legacy).
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NewAuthz { get; set; }

    /// <summary>
    /// Gets or sets the URL for revoking a certificate.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RevokeCert { get; set; }

    /// <summary>
    /// Gets or sets the URL for key rollover/change.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? KeyChange { get; set; }

    /// <summary>
    /// Gets or sets the directory metadata object, if present.
    /// </summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DirectoryMeta? Meta { get; set; }
}
