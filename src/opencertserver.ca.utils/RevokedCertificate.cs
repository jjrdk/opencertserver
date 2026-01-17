using System.Collections.ObjectModel;

namespace OpenCertServer.Ca.Utils;

public record RevokedCertificate
{
    public RevokedCertificate(
        byte[] serialNumber,
        DateTimeOffset revocationTime,
        params Span<CertificateExtension> extensions)
    {
        Serial = serialNumber;
        RevocationTime = revocationTime;
        Extensions = new ReadOnlyCollection<CertificateExtension>(extensions.ToArray());
    }

    public byte[] Serial { get; }
    public DateTimeOffset RevocationTime { get; }
    public IReadOnlyCollection<CertificateExtension> Extensions { get; }
}
