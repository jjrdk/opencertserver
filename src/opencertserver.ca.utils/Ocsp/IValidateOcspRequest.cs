namespace OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Defines the IValidateOcspRequest interface.
/// </summary>
/// <summary>
/// Represents the IValidateOcspRequest.
/// </summary>
public interface IValidateOcspRequest
{
    Task<string?> Validate(OcspRequest request);
}
