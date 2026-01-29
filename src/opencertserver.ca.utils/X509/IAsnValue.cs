namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;

/// <summary>
/// Defines an interface for ASN.1 values that can be encoded.
/// </summary>
public interface IAsnValue
{
    /// <summary>
    /// Encodes the ASN.1 value using the provided <see cref="AsnWriter"/>.
    /// </summary>
    /// <param name="writer">The <see cref="AsnWriter"/> to write content to.</param>
    /// <param name="tag">The optional <see cref="Asn1Tag"/> for the initial element.</param>
    void Encode(AsnWriter writer, Asn1Tag? tag = null);
}
