namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

using CertesSlim.Acme.Resource;

/// <summary>
/// Represents a request to retrieve or update an ACME authorization resource.
/// </summary>
public sealed class UpdateAuthorizationRequest
{
    /// <summary>
    /// Gets or sets the requested authorization status.
    /// </summary>
    public AuthorizationStatus? Status { get; set; }
}
