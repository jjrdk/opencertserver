namespace OpenCertServer.Ca.Utils;

public record struct RevokedCertificate
{
    internal RevokedCertificate(byte[] serialNumber, DateTimeOffset revocationTime, byte[]? extensions)
    {
        Serial = serialNumber;
        RevocationTime = revocationTime;
        Extensions = extensions;
    }

    public byte[] Serial { get; }
    public DateTimeOffset RevocationTime { get; }
    public byte[]? Extensions { get; }
}
