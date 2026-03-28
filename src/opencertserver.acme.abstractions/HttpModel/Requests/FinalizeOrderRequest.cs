namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

/// <summary>
/// Represents a request to finalize an ACME order with a CSR.
/// </summary>
public sealed class FinalizeOrderRequest
{
    /// <summary>
    /// Gets or sets the base64url-encoded CSR (Certificate Signing Request).
    /// </summary>
    public string? Csr { get; set; }
}
