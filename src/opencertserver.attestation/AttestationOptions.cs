namespace OpenCertServer.Attestation;

/// <summary>
/// Root configuration object for the attestation framework. Mapped from JSON section "Global" + "Providers".
/// </summary>
public sealed class AttestationOptions
{
    public string CloudContext { get; set; } = "Local";

    /// <summary>
    /// Optional explicit vendor preference. When null, the provider is selected based on runtime hardware detection.
    /// Valid values: "Intel", "AMD", "Apple".
    /// </summary>
    public string? VendorPreference { get; set; }

    /// <summary>
    /// Certificate revocation check mode. Defaults to <see cref="X509RevocationMode.Online"/> per spec 4.3.
    /// Set to <see cref="X509RevocationMode.NoCheck"/> in integration test environments where test certificates
    /// have no CRL/OCSP distribution points.
    /// </summary>
    public System.Security.Cryptography.X509Certificates.X509RevocationMode RevocationMode { get; set; } =
        System.Security.Cryptography.X509Certificates.X509RevocationMode.Online;

    public IntelSgxOptions IntelSgx { get; set; } = new();
    public AmdSevSnpOptions AmdSevSnp { get; set; } = new();
    public AppleSeOptions AppleSE { get; set; } = new();
}

public sealed class IntelSgxOptions
{
    public string PccsUrl { get; set; } = "https://pccs.confidentialcomputing.azure.com";
    public string RootCA { get; set; } = "intel_root.cer";
    public TimeSpan CertificateCacheTtl { get; set; } = TimeSpan.FromHours(24);
}

public sealed class AmdSevSnpOptions
{
    public string VpsUrl { get; set; } = "https://amd-vps.confidentialcomputing.azure.com";
    public string RootCA { get; set; } = "amd_root.cer";
    public TimeSpan CertificateCacheTtl { get; set; } = TimeSpan.FromHours(24);
}

public sealed class AppleSeOptions
{
    public string TeamId { get; set; } = string.Empty;
    public string AppId { get; set; } = string.Empty;
    public string VerifyUrl { get; set; } = "https://appattest.apple.com";

    /// <summary>
    /// When <c>true</c>, <see cref="AppleSeProvider.GenerateAndSignQuoteAsync"/> calls the
    /// DCAppAttestService native interop to generate an attestation object on the device.
    /// Only valid on macOS 11+ / iOS 14+ with the App Attest entitlement.
    ///
    /// When <c>false</c> (default), the provider operates in server-side verification mode:
    /// the <c>nonce</c> argument to <see cref="IAttestationProvider.GenerateAndSignQuoteAsync"/>
    /// must be the raw CBOR attestation object received from the iOS/macOS client, which is
    /// forwarded to Apple's verification endpoint.
    /// </summary>
    public bool UseDeviceAttestation { get; set; } = false;
}
