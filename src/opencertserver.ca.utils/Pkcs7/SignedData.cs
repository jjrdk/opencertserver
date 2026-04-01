namespace OpenCertServer.Ca.Utils.Pkcs7;

using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the SignedData structure as per PKCS#7 standard.
/// </summary>
/// <code>
/// SignedData ::= SEQUENCE {
///   version           Version,
///   digestAlgorithms  DigestAlgorithmIdentifiers,
///   contentInfo       ContentInfo,
///   certificates      [0] IMPLICIT Certificates OPTIONAL,
///   crls              [1] IMPLICIT CertificateRevocationLists OPTIONAL,
///   signerInfos       SignerInf///
///   IF ((certificates is present) AND
///      (any certificates with a type of other are present)) OR
///      ((crls is present) AND
///      (any crls with a type of other are present))
///   THEN version MUST be 5
///   ELSE
///      IF (certificates is present) AND
///         (any version 2 attribute certificates are present)
///      THEN version MUST be 4
///      ELSE
///         IF ((certificates is present) AND
///            (any version 1 attribute certificates are present)) OR
///            (any SignerInfo structures are version 3) OR
///            (encapContentInfo eContentType is other than id-data)
///         THEN version MUST be 3
///         ELSE version MUST be 1
/// </code>
public class SignedData : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SignedData"/> class.
    /// </summary>
    /// <param name="version">The version of the SignedData structure. Must be 1, 3, 4, or 5.</param>
    /// <param name="digestAlgorithms">The digest algorithms used for the content.</param>
    /// <param name="contentInfo">The content information.</param>
    /// <param name="certificates">The certificates included in the SignedData.</param>
    /// <param name="crls">The certificate revocation lists included in the SignedData.</param>
    /// <param name="signerInfos">The signer information for the SignedData.</param>
    public SignedData(
        BigInteger? version = null,
        DigestAlgorithmIdentifier[]? digestAlgorithms = null,
        ContentInfo? contentInfo = null,
        X509Certificate2[]? certificates = null,
        byte[][]? crls = null,
        SignerInfo[]? signerInfos = null)
    {
        Version = version ?? 1;
        DigestAlgorithms = digestAlgorithms ?? [];
        ContentInfo = contentInfo ?? new ContentInfo(new Oid("1.2.840.113549.1.7.1"), []);
        Certificates = certificates;
        Crls = crls;
        SignerInfos = signerInfos ?? [];
    }

    public SignedData(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Version = sequenceReader.ReadInteger();
        var digestAlgorithmsReader = sequenceReader.ReadSetOf();
        var digestAlgorithms = new List<DigestAlgorithmIdentifier>();
        while (digestAlgorithmsReader.HasData)
        {
            var digestAlgorithmReader = digestAlgorithmsReader.ReadSequence();
            var algorithmIdentifier = digestAlgorithmReader.ReadObjectIdentifier();
            var parameters = digestAlgorithmReader.ReadEncodedValue().ToArray();
            digestAlgorithms.Add(new DigestAlgorithmIdentifier(new Oid(algorithmIdentifier), parameters));
        }

        DigestAlgorithms = digestAlgorithms.ToArray();
        ContentInfo = new ContentInfo(sequenceReader);
        var tag = sequenceReader.PeekTag();
        if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            var certificateReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            var certificates = new List<X509Certificate2>();
            while (certificateReader.HasData)
            {
                var cert = X509CertificateLoader.LoadCertificate(certificateReader.ReadEncodedValue().Span);
                certificates.Add(cert);
            }

//            certificates.Reverse();
            Certificates = certificates.ToArray();
        }

        if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            var crlsReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            var crls = new List<byte[]>();
            while (crlsReader.HasData)
            {
                var crl = crlsReader.ReadEncodedValue();
                crls.Add(crl.ToArray());
            }

            Crls = crls.ToArray();
        }

        var signerInfos = new List<SignerInfo>();
        while (sequenceReader.HasData)
        {
            var signerInfoReader = sequenceReader.ReadSetOf();
            while (signerInfoReader.HasData)
            {
                var signerInfo = new SignerInfo(signerInfoReader);
                signerInfos.Add(signerInfo);
            }
        }

        SignerInfos = signerInfos.ToArray();
    }

    /// <summary>
    /// <para>
    /// Gets the version of the SignedData structure.
    /// </para>
    /// <para>
    /// Must be 1, 3, 4, or 5 depending on the presence of certain fields as per PKCS#7 standard.
    /// </para>
    /// </summary>
    public BigInteger Version { get; }

    /// <summary>
    /// Gets the digest algorithms used for the content.
    /// </summary>
    public DigestAlgorithmIdentifier[] DigestAlgorithms { get; }

    /// <summary>
    /// Gets the content information.
    /// </summary>
    public ContentInfo ContentInfo { get; }

    /// <summary>
    /// Gets the certificates included in the SignedData.
    /// </summary>
    public X509Certificate2[]? Certificates { get; }

    /// <summary>
    /// Gets the certificate revocation lists included in the SignedData.
    /// </summary>
    public byte[][]? Crls { get; }

    /// <summary>
    /// Gets the signer information for the SignedData.
    /// </summary>
    public SignerInfo[] SignerInfos { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteInteger(Version);
            using (writer.PushSetOf())
            {
                foreach (var digestAlgorithm in DigestAlgorithms)
                {
                    digestAlgorithm.Encode(writer);
                }
            }

            ContentInfo.Encode(writer);
            if (Certificates != null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    foreach (var cert in Certificates)
                    {
                        writer.WriteEncodedValue(cert.RawData);
                    }
                }
            }

            if (Crls != null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    foreach (var crl in Crls)
                    {
                        writer.WriteEncodedValue(crl);
                    }
                }
            }

            using (writer.PushSetOf())
            {
                foreach (var signerInfo in SignerInfos)
                {
                    signerInfo.Encode(writer);
                }
            }
        }
    }
}
