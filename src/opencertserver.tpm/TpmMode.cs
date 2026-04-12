namespace OpenCertServer.Tpm;

/// <summary>
/// Controls how the <see cref="TssTpmKeyProvider"/> connects to the TPM hardware or simulator.
/// </summary>
public enum TpmMode
{
    /// <summary>
    /// Use the Linux kernel resource manager at /dev/tpmrm0 (production Linux).
    /// </summary>
    Linux,

    /// <summary>
    /// Use the Windows TPM Base Services (TBS) device (production Windows).
    /// </summary>
    Windows,

    /// <summary>
    /// Connect to an IBM TPM2 software simulator over TCP (development / CI testing).
    /// </summary>
    Simulator
}

