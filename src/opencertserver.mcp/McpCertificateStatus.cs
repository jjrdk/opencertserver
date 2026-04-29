namespace OpenCertServer.Mcp;

/// <summary>
/// Represents the status of a certificate from a revocation-checking perspective.
/// Mirrors OCSP certificateStatus: good, revoked, or unknown.
/// </summary>
public enum McpCertificateStatus
{
       /// <summary>The certificate is valid and not revoked.</summary>
    Good = 1,

       /// <summary>The certificate has been revoked.</summary>
    Revoked = 2,

       /// <summary>The certificate status could not be determined (unknown).</summary>
    Unknown = 3
}
