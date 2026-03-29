namespace OpenCertServer.Ca.Utils.Ca;

public interface IStoreCaProfiles : IDisposable
{
    CaProfile GetProfile(string? name);
}
