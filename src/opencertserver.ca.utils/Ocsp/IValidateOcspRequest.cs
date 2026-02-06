namespace OpenCertServer.Ca.Utils.Ocsp;

public interface IValidateOcspRequest
{
    Task<string?> Validate(OcspRequest request);
}
