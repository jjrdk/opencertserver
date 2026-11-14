using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils.X509Extensions;

/// <summary>
/// Defines the X509 Issuing Distribution Point Extension
/// </summary>
public class IssuingDistributionPointExtension : X509Extension
{
    /// <summary>
    /// Initializes a new instance of the <see cref="IssuingDistributionPointExtension"/> class.
    /// </summary>
    /// <param name="uris">The URIs for the issuing distribution point.</param>
    /// <param name="isCritical">Indicates whether the extension is critical.</param>
    public IssuingDistributionPointExtension(
        IEnumerable<string> uris, bool isCritical)
        : base(Oids.IssuingDistributionPoint, EncodeIssuingDistributionPoint(uris), isCritical)
    {
    }

    private static byte[] EncodeIssuingDistributionPoint(IEnumerable<string> uris)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    foreach (var uri in uris)
                    {
                        writer.WriteCharacterString(
                            UniversalTagNumber.IA5String,
                            uri,
                            new Asn1Tag(TagClass.ContextSpecific, 6));
                    }
                }
        return writer.Encode();
    }
}
