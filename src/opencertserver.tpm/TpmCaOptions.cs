namespace OpenCertServer.Tpm;

using System;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Configuration options for TPM-backed CA profiles.
/// </summary>
public sealed class TpmCaOptions
{
    /// <summary>
    /// How to connect to the TPM.  Defaults to <see cref="TpmMode.Linux"/>.
    /// </summary>
    public TpmMode Mode { get; set; } = TpmMode.Linux;

    /// <summary>
    /// Hostname for the TPM simulator (only used when <see cref="Mode"/> is <see cref="TpmMode.Simulator"/>).
    /// Defaults to "localhost".
    /// </summary>
    public string SimulatorHost { get; set; } = "localhost";

    /// <summary>
    /// Port for the TPM simulator command channel.  Defaults to 2321.
    /// </summary>
    public int SimulatorPort { get; set; } = 2321;

    /// <summary>
    /// Port for the TPM simulator platform channel.  When <c>null</c> (the default)
    /// the platform port is assumed to be <see cref="SimulatorPort"/> + 1, which is
    /// the IBM SW TPM2 simulator convention.
    /// <para>
    /// Set this explicitly when running inside a Testcontainers environment where each
    /// container port is mapped to an independent random host port.
    /// </para>
    /// </summary>
    public int? SimulatorPlatformPort { get; set; } = null;

    /// <summary>
    /// Persistent handle for the RSA CA signing key.
    /// Change this if 0x81000001 conflicts with existing TPM usage on your platform.
    /// </summary>
    public uint RsaKeyHandle { get; set; } = 0x81000001;

    /// <summary>
    /// Persistent handle for the ECDsa CA signing key.
    /// Change this if 0x81000002 conflicts with existing TPM usage on your platform.
    /// </summary>
    public uint EcDsaKeyHandle { get; set; } = 0x81000002;

    /// <summary>
    /// X.500 distinguished name for the self-signed CA certificate, e.g. "CN=My TPM CA".
    /// </summary>
    public string CaSubjectName { get; set; } = "CN=TPM CA";

    /// <summary>
    /// Lifetime of the CA certificate itself.  Defaults to 5 years.
    /// </summary>
    public TimeSpan CaCertificateValidity { get; set; } = TimeSpan.FromDays(5 * 365);

    /// <summary>
    /// Lifetime of leaf certificates issued by this CA.  Defaults to 90 days.
    /// </summary>
    public TimeSpan IssuedCertificateValidity { get; set; } = TimeSpan.FromDays(90);

    /// <summary>
    /// OCSP response freshness window.  Defaults to 1 hour.
    /// </summary>
    public TimeSpan OcspFreshnessWindow { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Certificate store name used to persist the CA public certificate.
    /// Defaults to <see cref="StoreName.My"/>.
    /// </summary>
    public StoreName CertStoreName { get; set; } = StoreName.My;

    /// <summary>
    /// Certificate store location.  Defaults to <see cref="StoreLocation.CurrentUser"/>
    /// (no elevated permissions required).
    /// </summary>
    public StoreLocation CertStoreLocation { get; set; } = StoreLocation.CurrentUser;
}

