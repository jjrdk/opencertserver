namespace OpenCertServer.Ca.Utils.Ocsp;

public enum OcspResponseStatus
{
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6
}