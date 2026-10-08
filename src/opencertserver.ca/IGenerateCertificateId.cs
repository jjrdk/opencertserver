using System.Security.Cryptography;

namespace OpenCertServer.Ca;

public interface IGenerateCertificateId
{
    /// <summary>
    /// Generates a unique identifier for the given X.509 certificate.
    /// </summary>
    /// <returns>A unique identifier for the certificate.</returns>
    byte[] GenerateId();
}

public class RandomNumberCertificateIdGenerator : IGenerateCertificateId, IDisposable
{
    private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

    public byte[] GenerateId()
    {
        var randomNumber = new byte[16]; // 128-bit identifier
        _rng.GetBytes(randomNumber);
        return randomNumber;
    }

    public void Dispose()
    {
        _rng.Dispose();
    }
}
