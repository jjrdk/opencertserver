using System.Security.Cryptography;

namespace OpenCertServer.Ca.Tests.X509;

internal class OidComparer : IEqualityComparer<Oid>
{
    public  static readonly OidComparer Instance = new();

    private OidComparer()
    {
    }

    public bool Equals(Oid? x, Oid? y)
    {
        if (x is null && y is null)
        {
            return true;
        }

        if (x is null || y is null)
        {
            return false;
        }

        return x.Value == y.Value;
    }

    public int GetHashCode(Oid obj)
    {
        return obj.Value?.GetHashCode() ?? 0;
    }
}
