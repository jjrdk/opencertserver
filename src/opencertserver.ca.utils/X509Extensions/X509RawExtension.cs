using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils.X509Extensions;

public class X509RawExtension : X509Extension
{
    public X509RawExtension(
        Oid oid,
        bool isCritical,
        ReadOnlySpan<byte> rawData)
        : base(oid, rawData, isCritical)
    {
    }
}
