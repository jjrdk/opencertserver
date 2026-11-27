namespace OpenCertServer.Ca.Protocol;

/// <summary>
/// A registration authority's enrollment request to a backing certificate authority. Models the
/// POST <c>ca/{profile}/csr</c> call: the CSR, the selected profile, an optional delegated DNS scope
/// and optional validity window.
/// </summary>
public sealed record RaEnrollRequest(
    string CsrPem,
    string? Profile = null,
    string? DelegatedScope = null,
    DateTimeOffset? NotBefore = null,
    DateTimeOffset? NotAfter = null)
{
    /// <summary>The protocol version this request is expressed in.</summary>
    public string? ProtocolVersion { get; init; } = RaProtocol.RaProtocolVersion;
}

/// <summary>
/// The certificate authority's answer to a <see cref="RaEnrollRequest"/>. Exactly one of
/// <see cref="CertificatePem"/> or <see cref="Error"/> is populated.
/// </summary>
public sealed record RaEnrollResponse(
    string? CertificatePem,
    string? Error,
    string? ProtocolVersion = RaProtocol.RaProtocolVersion);

/// <summary>
/// A registration authority's revocation request to a backing certificate authority. Models the
/// DELETE <c>ca/revoke</c> call with its signed proof-of-possession.
/// </summary>
public sealed record RaRevokeRequest(
    string SerialNumberHex,
    string Reason,
    string SignatureBase64,
    string? DelegatedScope = null,
    string? ProtocolVersion = RaProtocol.RaProtocolVersion);

/// <summary>
/// The certificate authority's answer to a <see cref="RaRevokeRequest"/>.
/// </summary>
public sealed record RaRevokeResponse(
    bool Revoked,
    string? Error = null,
    string? ProtocolVersion = RaProtocol.RaProtocolVersion);
