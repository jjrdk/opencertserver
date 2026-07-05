namespace OpenCertServer.Acme.Abstractions.Services;

/// <summary>
/// Marker interface for device-attest-01 challenge validators.
/// Extends IValidateChallenges so device-attest can be injected via the same service locator.
/// </summary>
public interface IValidateDeviceAttestChallenges : IValidateChallenges
{
}
