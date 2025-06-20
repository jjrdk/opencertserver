namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

public sealed class FileCertificatePersistenceStrategy : ICertificatePersistenceStrategy
{
    private readonly string _relativeFilePath;

    public FileCertificatePersistenceStrategy(string relativeFilePath)
    {
        _relativeFilePath = relativeFilePath;
    }

    public Task Persist(CertificateType persistenceType, byte[] certificate)
    {
        return File.WriteAllBytesAsync(GetCertificatePath(persistenceType), certificate);
    }

    public async Task<byte[]?> RetrieveAccountCertificate()
    {
        var bytes = await ReadFile(CertificateType.Account);
        return bytes;
    }

    public async Task<X509Certificate2?> RetrieveSiteCertificate()
    {
        var bytes = await ReadFile(CertificateType.Site);
#if NET8_0
        return bytes == null ? null : new X509Certificate2(bytes);
#else
        return bytes == null ? null :  X509CertificateLoader.LoadCertificate(bytes);
#endif
    }

    private async Task<byte[]?> ReadFile(CertificateType persistenceType)
    {
        return !File.Exists(GetCertificatePath(persistenceType))
            ? null
            : await File.ReadAllBytesAsync(GetCertificatePath(persistenceType));
    }

    private string GetCertificatePath(CertificateType persistenceType)
    {
        return $"{_relativeFilePath}_{persistenceType}";
    }
}
