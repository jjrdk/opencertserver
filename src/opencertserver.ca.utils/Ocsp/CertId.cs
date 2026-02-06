using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Defines a CertID
/// </summary>
/// <code>
/// SEQUENCE {
///     hashAlgorithm       AlgorithmIdentifier,
///     issuerNameHash      OCTET STRING, -- Hash of issuer's DN
///     issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
///     serialNumber        CertificateSerialNumber
/// }
/// </code>
public class CertId : IAsnValue
{
    public CertId(AlgorithmIdentifier algorithm, byte[] issuerNameHash, byte[] issuerKeyHash, byte[] serialNumber)
    {
        Algorithm = algorithm;
        IssuerNameHash = issuerNameHash;
        IssuerKeyHash = issuerKeyHash;
        SerialNumber = serialNumber;
    }

    public CertId(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Algorithm = new AlgorithmIdentifier(sequenceReader);
        IssuerNameHash = sequenceReader.ReadOctetString();
        IssuerKeyHash = sequenceReader.ReadOctetString();
        SerialNumber = sequenceReader.ReadIntegerBytes().ToArray();
        sequenceReader.ThrowIfNotEmpty();
    }

    public AlgorithmIdentifier Algorithm { get; }

    public byte[] IssuerNameHash { get; }

    public byte[] IssuerKeyHash { get; }

    public byte[] SerialNumber { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            Algorithm.Encode(writer);
            writer.WriteOctetString(IssuerNameHash);
            writer.WriteOctetString(IssuerKeyHash);
            writer.WriteInteger(SerialNumber);
        }
    }
}
