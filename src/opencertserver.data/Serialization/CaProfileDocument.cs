namespace OpenCertServer.Data.Serialization;

/// <summary>
/// JSON-serializable projection of an <see cref="OpenCertServer.Ca.Utils.Ca.CaProfile"/>, holding the
/// profile's private key and certificates as PEM so it can round-trip through a relational column
/// without exposing cryptographic handles to the EF model.
/// </summary>
internal sealed class CaProfileDocument
{
    /// <summary>The profile name, also the relational primary key.</summary>
    public required string Name { get; set; }

    /// <summary>Whether unauthenticated enrollment is allowed.</summary>
    public bool AllowPublicEnrollment { get; set; }

    /// <summary>PEM-encoded private key (PKCS#8 for RSA, SEC1 for ECDsa).</summary>
    public required string PrivateKeyPem { get; set; }

    /// <summary>The private-key algorithm, one of <c>RSA</c> or <c>ECDsa</c>.</summary>
    public required string PrivateKeyType { get; set; }

    /// <summary>PEM-encoded issuing certificate chain, in order.</summary>
    public required List<string> CertificateChain { get; set; }

    /// <summary>PEM-encoded certificates published to EST clients.</summary>
    public List<string> PublishedCertificateChain { get; set; } = [];

    /// <summary>PEM-encoded explicit trust anchors.</summary>
    public List<string> TrustAnchors { get; set; } = [];

    /// <summary>PEM-encoded additional chain certificates.</summary>
    public List<string> AdditionalChainCertificates { get; set; } = [];

    /// <summary>Validity period for certificates issued by the profile.</summary>
    public TimeSpan CertificateValidity { get; set; }

    /// <summary>Current CRL number, encoded as an invariant-culture decimal string.</summary>
    public string CrlNumber { get; set; } = "0";

    /// <summary>OIDs of CSR extensions permitted to be copied into issued certificates.</summary>
    public List<string> AllowedCsrExtensions { get; set; } = [];

    /// <summary>Certificate policy identifiers the CA asserts into issued certificates.</summary>
    public List<string> CertificatePolicies { get; set; } = [];

    /// <summary>Key usage asserted into issued certificates (the <c>X509KeyUsageFlags</c> value), replacing the CSR value when set.</summary>
    public long? KeyUsage { get; set; }

    /// <summary>Extended key usage OIDs asserted into issued certificates.</summary>
    public List<string>? ExtendedKeyUsages { get; set; }

    /// <summary>OCSP freshness window for responses issued by the profile.</summary>
    public TimeSpan OcspFreshnessWindow { get; set; }

    /// <summary>PEM-encoded OCSP signing certificate, or null when the CA certificate signs responses.</summary>
    public string? OcspSigningCertificatePem { get; set; }

    /// <summary>PEM-encoded OCSP signing private key, or null when absent.</summary>
    public string? OcspSigningKeyPem { get; set; }

    /// <summary>The OCSP signing key algorithm, or null when absent.</summary>
    public string? OcspSigningKeyType { get; set; }
}
