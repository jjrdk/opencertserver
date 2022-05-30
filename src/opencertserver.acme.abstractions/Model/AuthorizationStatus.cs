namespace OpenCertServer.Acme.Abstractions.Model
{
    public enum AuthorizationStatus
    {
        Pending,
        Valid,
        Invalid,
        Revoked,
        Deactivated,
        Expired
    }
}
