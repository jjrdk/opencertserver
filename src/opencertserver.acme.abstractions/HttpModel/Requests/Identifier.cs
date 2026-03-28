namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

/// <summary>
/// Defines an identifier as used in ACME order or authorization requests.
/// </summary>
public sealed class Identifier
{
    /// <summary>
    /// Gets or sets the identifier type (e.g., dns, ip).
    /// </summary>
    public string? Type { get; set; }
    /// <summary>
    /// Gets or sets the identifier value (e.g., domain name).
    /// </summary>
    public string? Value { get; set; }
}
