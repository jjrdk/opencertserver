namespace OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Defines the IValidateOcspRequest interface.
/// </summary>
/// <summary>
/// Represents the IValidateOcspRequest.
/// </summary>
public interface IValidateOcspRequest
{
    /// <summary>
    /// Validates the OCSP request. Returns null when the request is valid, or the appropriate
    /// <see cref="OcspResponseStatus"/> error code when the request must be rejected.
    /// </summary>
    Task<OcspResponseStatus?> Validate(OcspRequest request);
}
