namespace OpenCertServer.Ca.Protocol;

/// <summary>
/// The single source of truth for the RA ↔ CA wire contract: the request paths, claim and header
/// names, the revocation proof-of-possession message, and the negotiated protocol version. Both the
/// outbound registration authority (<c>opencertserver.ra</c>) and the certificate authority
/// (<c>opencertserver.ca.server</c>) read these constants, so changing the contract on one side cannot
/// silently desynchronize the other.
/// </summary>
public static class RaProtocol
{
    /// <summary>The current protocol version both sides negotiate against.</summary>
    public const string RaProtocolVersion = "1";

    /// <summary>The HTTP request header an RA may send to declare the protocol version it targets.</summary>
    public const string RaProtocolVersionHeader = "X-Ra-Protocol-Version";

    /// <summary>Protocol versions the certificate authority accepts. Version negotiation is additive.</summary>
    public static readonly IReadOnlySet<string> SupportedVersions =
        new HashSet<string>([RaProtocolVersion], StringComparer.Ordinal);

    /// <summary>The authenticated registration-authority identifier claim.</summary>
    public const string RaIdClaim = "ra";

    /// <summary>The requested delegated DNS scope claim.</summary>
    public const string DelegatedSubjectClaim = "delegated-subject";

    /// <summary>The HTTP header used by an RA client to select a delegated DNS scope.</summary>
    public const string DelegatedSubjectHeader = "X-Delegated-Subject";

    /// <summary>The CA endpoint that signs a CSR against the default profile.</summary>
    public const string CsrPath = "ca/csr";

    /// <summary>Format for the CA endpoint that signs a CSR against a named profile.</summary>
    public const string ProfileCsrPathFormat = "ca/{0}/csr";

    /// <summary>The CA endpoint that revokes a certificate by serial number.</summary>
    public const string RevokePath = "ca/revoke";

    /// <summary>Query parameter carrying the certificate serial number (hex) for a revocation.</summary>
    public const string QuerySn = "sn";

    /// <summary>Query parameter carrying the revocation reason for a revocation.</summary>
    public const string QueryReason = "reason";

    /// <summary>Query parameter carrying the base64 proof-of-possession signature for a revocation.</summary>
    public const string QuerySignature = "signature";

    /// <summary>The CA endpoint that publishes the certificate revocation list.</summary>
    public const string CrlPath = "ca/crl";

    /// <summary>Format for the CA endpoint that publishes the certificate revocation list for a named profile.</summary>
    public const string ProfilesPath = "ca/profiles";

    /// <summary>Format for the CA endpoint that publishes the revocation list for a named profile.</summary>
    public const string ProfileCrlPathFormat = "ca/{0}/crl";

    /// <summary>The digest used for the revocation proof-of-possession signature.</summary>
    public const string SignatureHashAlgorithm = "SHA256";

    /// <summary>The MIME type of a PKCS#10 certificate signing request.</summary>
    public const string CsrMimeType = "application/pkcs10";

    /// <summary>Builds the CSR path for the given profile, or the default-profile path when null/empty.</summary>
    public static string CsrPathFor(string? profile)
    {
        if (string.IsNullOrWhiteSpace(profile))
        {
            return CsrPath;
        }

        return string.Format(System.Globalization.CultureInfo.InvariantCulture,
            ProfileCsrPathFormat, Uri.EscapeDataString(profile));
    }

    /// <summary>
    /// Builds the canonical revocation proof-of-possession message, signed by the RA identity key.
    /// The serial number hex and the reason name are concatenated with no separator; both sides must
    /// agree on this exact string, which is why it lives here and not in either implementation.
    /// </summary>
    public static string BuildRevocationMessage(string serialNumberHex, string reasonName)
    {
        return serialNumberHex + reasonName;
    }

    /// <summary>
    /// Reports whether a declared protocol version (or absence, which the CA treats as the current
    /// version for backwards compatibility) is one the certificate authority accepts.
    /// </summary>
    public static bool IsSupportedVersion(string? declaredVersion)
    {
        return string.IsNullOrWhiteSpace(declaredVersion)
               || SupportedVersions.Contains(declaredVersion);
    }
}
