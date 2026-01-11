using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils.X509Extensions;

public class X509DeltaCrlIndicatorExtension : X509Extension
{
    public X509DeltaCrlIndicatorExtension(ReadOnlySpan<byte> crlNumber, bool isCritical)
        : base(new Oid("2.5.29.27", "Delta CRL Indicator"), crlNumber, isCritical)
    {
    }

    public BigInteger CrlNumber
    {
        get { return new BigInteger(RawData); }
    }
}
