using System.Security.Cryptography;

namespace OpenCertServer.Ca.Utils;

public abstract record CrlExtension
{
    protected CrlExtension(
        Oid oid,
        bool isCritical)
    {
        Oid = oid;
        IsCritical = isCritical;
    }

    public Oid Oid { get; }
    public bool IsCritical { get; }
}

public record RawCrlExtension : CrlExtension
{
    public RawCrlExtension(
        Oid oid,
        bool isCritical,
        ReadOnlyMemory<byte> rawData) : base(oid, isCritical)
    {
        RawData = rawData.ToArray();
    }

    public byte[] RawData { get; }
}
