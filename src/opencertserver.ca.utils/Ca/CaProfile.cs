using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca;

public record CaProfile : IDisposable
{
    private BigInteger _crlNumber;
    public required string Name { get; init; }
    public required AsymmetricAlgorithm PrivateKey { get; init; }
    public required X509Certificate2Collection CertificateChain { get; init; }
    public TimeSpan CertificateValidity { get; init; }

    public BigInteger CrlNumber
    {
        get { return _crlNumber; }
        init { _crlNumber = value; }
    }

    public BigInteger GetNextCrlNumber()
    {
        _crlNumber += BigInteger.One;
        return CrlNumber;
    }

    public void Dispose()
    {
        PrivateKey.Dispose();
        foreach (var cert in CertificateChain)
        {
            cert.Dispose();
        }
        GC.SuppressFinalize(this);
    }
}
