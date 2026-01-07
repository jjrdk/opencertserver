using System.Security.Cryptography;

namespace OpenCertServer.Ca.Utils;

public record AccessDescription
{
    public AccessDescription(Oid accessMethod, GeneralName accessLocation)
    {
        AccessMethod = accessMethod;
        AccessLocation = accessLocation;
    }

    public Oid AccessMethod { get; init; }
    public GeneralName AccessLocation { get; init; }
}
