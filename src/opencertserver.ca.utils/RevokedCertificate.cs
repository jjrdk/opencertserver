using OpenCertServer.Ca.Utils.X509Extensions;

namespace OpenCertServer.Ca.Utils;

using System.Collections.ObjectModel;
using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

public class RevokedCertificate : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RevokedCertificate"/> class.
    /// </summary>
    /// <param name="serialNumber">The serial number of the certificate.</param>
    /// <param name="revocationTime">The revocation time.</param>
    /// <param name="extensions">The certificate extensions.</param>
    public RevokedCertificate(
        byte[] serialNumber,
        DateTimeOffset revocationTime,
        params Span<CertificateExtension> extensions)
    {
        Serial = serialNumber;
        RevocationTime = revocationTime;
        Extensions = new ReadOnlyCollection<CertificateExtension>(extensions.ToArray());
    }

    /// <summary>
    /// Gets the serial number of the revoked certificate.
    /// </summary>
    public byte[] Serial { get; }

    /// <summary>
    /// Gets the revocation time of the certificate.
    /// </summary>
    public DateTimeOffset RevocationTime { get; }

    /// <summary>
    /// Get the certificate extensions.
    /// </summary>
    public IReadOnlyCollection<CertificateExtension> Extensions { get; }

    /// <inheritdoc />
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
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
