using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OpenCertServer.Ca;

public class InMemoryCertificateStore : IStoreCertificates
{
    private readonly X509Certificate2 _issuerCertificate;
    private byte[] _crlBytes;
    private readonly Dictionary<string, (DateTimeOffset, X509RevocationReason)?> _certificates = new();

    public InMemoryCertificateStore(X509Certificate2 issuerCertificate)
    {
        if (!issuerCertificate.HasPrivateKey)
        {
            throw new ArgumentException("Issuer certificate must have a private key", nameof(issuerCertificate));
        }

        _issuerCertificate = issuerCertificate;
        _crlBytes = new CertificateRevocationListBuilder().Build(_issuerCertificate,
            BigInteger.Zero,
            DateTimeOffset.UtcNow.AddDays(1), HashAlgorithmName.SHA256);
    }

    public void AddCertificate(X509Certificate2 certificate)
    {
        _certificates.Add(certificate.GetSerialNumberString(), null);
    }

    public bool RemoveCertificate(string serialNumber, X509RevocationReason reason)
    {
        var hasCert = _certificates.TryGetValue(serialNumber, out var value);
        if (!hasCert || value != null)
        {
            return false;
        }

        _certificates[serialNumber] = (DateTimeOffset.UtcNow, reason);
        var builder = CertificateRevocationListBuilder.Load(_crlBytes, out var sn);
        builder.AddEntry(Encoding.UTF8.GetBytes(serialNumber), DateTimeOffset.UtcNow, reason);
        _crlBytes = builder.Build(_issuerCertificate, sn + 1, DateTimeOffset.UtcNow.AddDays(1),
            HashAlgorithmName.SHA256);
        return true;
    }

    public byte[] GetRevocationList()
    {
        return _crlBytes;
    }
}
