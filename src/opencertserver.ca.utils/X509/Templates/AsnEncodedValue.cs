namespace OpenCertServer.Ca.Utils.X509.Templates;

using System.Formats.Asn1;

/// <summary>
/// Represents a pre-encoded ASN.1 value.
/// </summary>
public sealed class AsnEncodedValue(byte[] encodedValue) : IAsnValue
{
    /// <summary>
    /// Gets the encoded ASN.1 value.
    /// </summary>
    public byte[] EncodedValue { get; } = encodedValue;

    /// <inheritdoc />
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.WriteEncodedValue(EncodedValue);
    }
}

