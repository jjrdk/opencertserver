using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils.X509Extensions;

public class X509FreshestCrlExtension : X509Extension
{
    public X509FreshestCrlExtension(ReadOnlySpan<byte> freshestCrl, bool isCritical)
        : base(new Oid("2.5.29.46"), freshestCrl, isCritical)
    {
        var reader = new AsnReader(freshestCrl.ToArray(), AsnEncodingRules.DER);
    }
}
