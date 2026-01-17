using System.Collections.ObjectModel;
using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils;

public class RevokedCertificate : AsnValue
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

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteInteger(Serial);
            writer.WriteGeneralizedTime(RevocationTime);
            if (Extensions.Count > 0)
            {
                using (writer.PushSequence())
                {
                    foreach (var ext in Extensions)
                    {
                        ext.Encode(writer);
                    }
                }
            }
        }
    }
}
