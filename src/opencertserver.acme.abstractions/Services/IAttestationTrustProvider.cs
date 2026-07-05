namespace OpenCertServer.Acme.Abstractions.Services;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Provides the set of trusted manufacturer root CA certificates used to verify
/// AIK certificate chains during device-attest-01 challenge validation.
/// </summary>
public interface IAttestationTrustProvider
{
    /// <summary>Returns the trusted root CA certificates (e.g. Apple Attestation CA, Intel ME, AMD PSP).</summary>
    X509Certificate2Collection GetTrustedRoots();
}
