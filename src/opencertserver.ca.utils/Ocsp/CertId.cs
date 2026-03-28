namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

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
    /// <summary>
    /// Initializes a new instance of the <see cref="CertId"/> class.
    /// </summary>
    public CertId(AlgorithmIdentifier algorithm, byte[] issuerNameHash, byte[] issuerKeyHash, byte[] serialNumber)
    {
        Algorithm = algorithm;
        IssuerNameHash = issuerNameHash;
        IssuerKeyHash = issuerKeyHash;
        SerialNumber = serialNumber;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertId"/> class.
    /// </summary>
    public CertId(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Algorithm = new AlgorithmIdentifier(sequenceReader);
        IssuerNameHash = sequenceReader.ReadOctetString();
        IssuerKeyHash = sequenceReader.ReadOctetString();
        SerialNumber = sequenceReader.ReadIntegerBytes().ToArray();
        sequenceReader.ThrowIfNotEmpty();
    }

    /// <summary>
    /// Executes the Create operation.
    /// </summary>
    public static CertId Create(X509Certificate2 certificate, HashAlgorithmName hashAlgorithm)
    {
        var hasher = hashAlgorithm.CreateHashAlgorithm();
        return new CertId(
            new AlgorithmIdentifier(hashAlgorithm.GetHashAlgorithmOid()),
            hasher.ComputeHash(certificate.IssuerName.RawData),
            hasher.ComputeHash(certificate.GetPublicKey()),
            certificate.SerialNumberBytes.ToArray());
    }

    /// <summary>
    /// Gets the hash algorithm identifier used in this certificate identifier.
    /// </summary>
    public AlgorithmIdentifier Algorithm { get; }

    /// <summary>
    /// Gets the hash of the issuer distinguished name.
    /// </summary>
    public byte[] IssuerNameHash { get; }

    /// <summary>
    /// Gets the hash of the issuer public key.
    /// </summary>
    public byte[] IssuerKeyHash { get; }

    /// <summary>
    /// Gets the certificate serial number bytes.
    /// </summary>
    public byte[] SerialNumber { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        Algorithm.Encode(writer);
        writer.WriteOctetString(IssuerNameHash);
        writer.WriteOctetString(IssuerKeyHash);
        writer.WriteInteger(SerialNumber);
        writer.PopSequence(tag);
    }
}
