namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

using CertesSlim.Acme.Resource;

/// <summary>
/// Represents an ACME certificate revocation request.
/// </summary>
public sealed class RevokeCertificateRequest
{
    /// <summary>
    /// Gets or sets the certificate to revoke, encoded as base64url DER.
    /// </summary>
    public string? Certificate { get; set; }

    /// <summary>
    /// Gets or sets the optional revocation reason.
    /// </summary>
    public RevocationReason? Reason { get; set; }
}

