using System.Collections.ObjectModel;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils;

/// <summary>
/// Defines a Certificate Revocation List (CRL).
/// </summary>
public class CertificateRevocationList
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateRevocationList"/> class.
    /// </summary>
    /// <param name="version">The CRL format version.</param>
    /// <param name="crlNumber">The CRL number.</param>
    /// <param name="signature">The CRL signature.</param>
    /// <param name="signatureAlgorithm">The signature algorithm used.</param>
    /// <param name="issuer">The distinguished name of the CRL issuer.</param>
    /// <param name="thisUpdate">The <see cref="DateTimeOffset"/> when the CRL was issued.</param>
    /// <param name="nextUpdate">The <see cref="DateTimeOffset"/> when the next CRL will be issued.</param>
    /// <param name="revokedCertificates">The <see cref="List{T}"/> of revoked <see cref="RevokedCertificates"/>.</param>
    public CertificateRevocationList(
        CrlVersion version,
        BigInteger crlNumber,
        byte[] signature,
        HashAlgorithmName signatureAlgorithm,
        X500DistinguishedName issuer,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        params IEnumerable<RevokedCertificate> revokedCertificates)
    {
        Version = version;
        CrlNumber = crlNumber;
        Signature = signature;
        SignatureAlgorithm = signatureAlgorithm;
        Issuer = issuer;
        ThisUpdate = thisUpdate;
        NextUpdate = nextUpdate;
        RevokedCertificates = revokedCertificates.ToList().AsReadOnly();
    }

    /// <summary>
    /// Gets the list of revoked certificates.
    /// </summary>
    public ReadOnlyCollection<RevokedCertificate> RevokedCertificates { get; set; }

    /// <summary>
    /// Gets the CRL version.
    /// </summary>
    public CrlVersion Version { get; }

    /// <summary>
    /// Gets the CRL number.
    /// </summary>
    public BigInteger CrlNumber { get; }

    /// <summary>
    /// Gets the CRL signature.
    /// </summary>
    public byte[] Signature { get; }

    /// <summary>
    /// Gets the signature algorithm used.
    /// </summary>
    public HashAlgorithmName SignatureAlgorithm { get; }

    /// <summary>
    /// Gets the issuer distinguished name.
    /// </summary>
    public X500DistinguishedName Issuer { get; }

    /// <summary>
    /// Gets the <see cref="DateTimeOffset"/> for this update.
    /// </summary>
    public DateTimeOffset ThisUpdate { get; }

    /// <summary>
    /// Gets the <see cref="DateTimeOffset"/> for the next update.
    /// </summary>
    public DateTimeOffset? NextUpdate { get; }

    /// <summary>
    /// Defines the CRL version.
    /// </summary>
    public enum CrlVersion
    {
        V1 = 0,
        V2 = 1,
        V3 = 2
    }

    /// <summary>
    /// Reads and verifies a DER-encoded CRL using the issuer's public key.
    /// </summary>
    /// <param name="crl">The DER encoded certificate revocation list.</param>
    /// <param name="issuerPublicKey">The public key of the issuer.</param>
    /// <returns>A populated instance of a <see cref="CertificateRevocationList"/>.</returns>
    /// <exception cref="CryptographicException">Raised if the signature cannot be verified or the content is malformed.</exception>
    public static CertificateRevocationList Load(ReadOnlyMemory<byte> crl, AsymmetricAlgorithm issuerPublicKey)
    {
        // CRL ::= SEQUENCE {
        //     tbsCertList             TBSCertList,
        //     signatureAlgorithm      AlgorithmIdentifier,
        //     signatureValue          BIT STRING
        // }

        var tbsSpan = ReadSignedContent(crl);

        BigInteger crlNumber = 0;

        var reader = new AsnReader(crl, AsnEncodingRules.DER);
        var certificateList = reader.ReadSequence();
        var tbsCertList = certificateList.ReadSequence();
        var algoIdentifier = certificateList.ReadSequence();
        reader.ThrowIfNotEmpty();
        var signature = certificateList.ReadBitString(out _, Asn1Tag.PrimitiveBitString);

        var signatureAlgo = GetHashAlgorithmFromOid(algoIdentifier.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier));

        if (!VerifySignature(tbsSpan, signature, issuerPublicKey, signatureAlgo))
        {
            throw new CryptographicException("CRL signature verification failed.");
        }

        var version = ReadVersion(tbsCertList);

        // Discard algorithm identifier as it is supposed to match the outer one
        _ = tbsCertList.ReadSequence();

        var distinguishedName = ReadDistinguishedName(ref tbsCertList);

        // thisUpdate
        var thisUpdate = ReadX509Time(ref tbsCertList);

        // nextUpdate
        var nextUpdate = ReadX509TimeOpt(ref tbsCertList);

        // revokedCertificates
        var list = ReadRevokedCertificates(ref tbsCertList, version);

        // TODO: Handle extensions
//
//            if (version > 0 && tbsCertList.HasData)
//            {
//                var crlExtensionsExplicit =
//                    tbsCertList.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
//                var crlExtensions = crlExtensionsExplicit.ReadSequence();
//                crlExtensionsExplicit.ThrowIfNotEmpty();
//
//                while (crlExtensions.HasData)
//                {
//                    var extension = crlExtensions.ReadSequence();
//                    Oid? extnOid = null; //Oids.GetSharedOrNullOid(ref extension);
//
//                    if (extnOid is null)
//                    {
//                        extension.ReadObjectIdentifier();
//                    }
//
//                    if (extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
//                    {
//                        extension.ReadBoolean();
//                    }
//
//                    if (!extension.TryReadPrimitiveOctetString(out var extnValue))
//                    {
//                        throw new CryptographicException("Invalid DER encoding for CRL extension value.");
//                    }
//
//                    // Since we're only matching against OIDs that come from GetSharedOrNullOid
//                    // we can use ReferenceEquals and skip the Value string equality check in
//                    // the Oid.ValueEquals extension method (as it will always be preempted by
//                    // the ReferenceEquals or will evaulate to false).
//                    if (ReferenceEquals(extnOid, new Oid()))
//                    {
//                        var crlNumberReader = new AsnValueReader(
//                            extnValue,
//                            AsnEncodingRules.DER);
//
//                        crlNumber = crlNumberReader.ReadInteger();
//                        crlNumberReader.ThrowIfNotEmpty();
//                    }
//                }
//            }
//
//            tbsCertList.ThrowIfNotEmpty();

        return new CertificateRevocationList(
            (CrlVersion)version,
            crlNumber,
            signature,
            signatureAlgo,
            distinguishedName,
            thisUpdate,
            nextUpdate,
            list);
    }

    /// <summary>
    /// Verifies the signature of a DER-encoded CRL using the issuer's public key.
    /// </summary>
    /// <param name="crl">The DER encoded CRL.</param>
    /// <param name="issuerPublicKey">The public key of the CRL issuer.</param>
    /// <returns><c>True</c> if the signature is verified, otherwise <c>False</c></returns>
    /// <exception cref="CryptographicException">Thrown if the content is malformed.</exception>
    public static bool VerifyCrlSignature(ReadOnlyMemory<byte> crl, AsymmetricAlgorithm issuerPublicKey)
    {
        var tbsSpan = ReadSignedContent(crl);

        // Now read the outer SEQUENCE again to get to signatureAlgorithm and signatureValue
        var reader = new AsnReader(crl, AsnEncodingRules.DER);
        var certificateList = reader.ReadSequence(Asn1Tag.Sequence);
        reader.ThrowIfNotEmpty(); // Ensure we consumed only tbsCertList so far? No — continue

        // 1. Read tbsCertList (first SEQUENCE)
        _ = certificateList.ReadSequence(Asn1Tag.Sequence);

        // 2. Read signatureAlgorithm
        var signatureAlgorithm = certificateList.ReadSequence(Asn1Tag.Sequence);
        var oid = signatureAlgorithm.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);

        // Map OID to HashAlgorithmName
        var hashAlgorithm = GetHashAlgorithmFromOid(oid);

        // 3. Read signatureValue (BIT STRING)
        var signatureValue = certificateList.ReadBitString(out var unusedBits, Asn1Tag.ConstructedBitString);
        if (unusedBits != 0)
            throw new CryptographicException("Signature BIT STRING has unused bits != 0");
        certificateList.ThrowIfNotEmpty();

        // Remove leading zero if present (some implementations add it)
        var signature = signatureValue.Length > 0 && signatureValue[0] == 0
            ? signatureValue.AsSpan(1).ToArray()
            : signatureValue;
        return VerifySignature(tbsSpan, signature, issuerPublicKey, hashAlgorithm);
    }

    private static ReadOnlySpan<byte> ReadSignedContent(ReadOnlyMemory<byte> crlDer)
    {
        // Read outer SEQUENCE, get content span (tbs + alg + sig)
        AsnDecoder.ReadSequence(crlDer.Span, AsnEncodingRules.DER, out var contentOffset, out var contentLength,
            out _, Asn1Tag.Sequence);
        var contentSpan = crlDer.Span.Slice(contentOffset, contentLength);

        // Read tbsCertList SEQUENCE, calculate its full encoded length
        AsnDecoder.ReadSequence(contentSpan, AsnEncodingRules.DER, out var tbsOffset, out var tbsLength, out _,
            Asn1Tag.Sequence);
        var tbsSpan = contentSpan[..(tbsOffset + tbsLength)];
        return tbsSpan;
    }

    private static bool VerifySignature(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, AsymmetricAlgorithm publicKey, HashAlgorithmName hashAlgorithm)
    {
        return publicKey switch
        {
            RSA rsa => rsa.VerifyData(data.ToArray(), signature.ToArray(), hashAlgorithm, RSASignaturePadding.Pss),
            ECDsa ecdsa => ecdsa.VerifyData(data.ToArray(), signature.ToArray(), hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence),
            _ => throw new NotSupportedException($"Public key type {publicKey.GetType()} not supported.")
        };
    }

    private static HashAlgorithmName GetHashAlgorithmFromOid(string oid)
    {
        return oid switch
        {
            "1.2.840.113549.1.1.10"=> HashAlgorithmName.SHA256, // rsassaPss
            "1.2.840.113549.1.1.11" => HashAlgorithmName.SHA256, // sha256WithRSAEncryption
            "1.2.840.113549.1.1.12" => HashAlgorithmName.SHA384,
            "1.2.840.113549.1.1.13" => HashAlgorithmName.SHA512,
            "1.2.840.113549.1.1.5" => HashAlgorithmName.SHA1, // sha1WithRSAEncryption
            "1.2.840.10045.4.3.2" => HashAlgorithmName.SHA256, // ecdsa-with-SHA256
            "1.2.840.10045.4.3.3" => HashAlgorithmName.SHA384,
            "1.2.840.10045.4.3.4" => HashAlgorithmName.SHA512,
            "1.2.840.10045.4.1" => HashAlgorithmName.SHA1, // ecdsa-with-SHA1
            _ => throw new CryptographicException($"Unsupported signature algorithm OID: {oid}")
        };
    }

    private static int ReadVersion(AsnReader tbsCertList)
    {
        var version = 0;

        if (tbsCertList.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
        {
            // https://datatracker.ietf.org/doc/html/rfc5280#section-5.1 says the only
            // version values are v1 (0) and v2 (1).
            //
            // Since v1 (0) is supposed to not write down the version value, v2 (1) is the
            // only legal value to read.
            if (!tbsCertList.TryReadInt32(out version) || version != 1)
            {
                throw new CryptographicException("Invalid CRL version.");
            }
        }

        return version;
    }

    private static X500DistinguishedName ReadDistinguishedName(ref AsnReader tbsCertList)
    {
        // X500DN
        var distinguishedName = new X500DistinguishedNameBuilder();
        var issuerSequence = tbsCertList.ReadSequence();
        while (issuerSequence.HasData)
        {
            var dnSet = issuerSequence.ReadSetOf();
            var dnSeq = dnSet.ReadSequence(Asn1Tag.Sequence);
            var dnAttrType = dnSeq.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier);
            var dnAttrValue = dnSeq.ReadCharacterString(UniversalTagNumber.PrintableString);
            distinguishedName.Add(dnAttrType, dnAttrValue, UniversalTagNumber.PrintableString);
        }

        return distinguishedName.Build();
    }

    private static List<RevokedCertificate> ReadRevokedCertificates(ref AsnReader tbsCertList, int version)
    {
        List<RevokedCertificate> list = [];
        if (!tbsCertList.HasData || !tbsCertList.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
        {
            return list;
        }
        var revokedCertificates = tbsCertList.ReadSequence();

        while (revokedCertificates.HasData)
        {
            var valueReader = revokedCertificates.ReadSequence();
            var serial = valueReader.ReadIntegerBytes().ToArray();
            var revocationTime = ReadX509Time(ref valueReader);
            byte[]? extensions = null;

            if (version > 0 && valueReader.HasData)
            {
                if (!valueReader.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
                {
                    throw new CryptographicException("Invalid DER encoding for revoked certificate extensions.");
                }

                extensions = valueReader.ReadEncodedValue().ToArray();
            }

            var revokedCertificate = new RevokedCertificate(serial, revocationTime, extensions);
            list.Add(revokedCertificate);
        }

        return list;
    }

    private static DateTimeOffset ReadX509Time(ref AsnReader reader)
    {
        return reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime)
            ? reader.ReadUtcTime()
            : reader.ReadGeneralizedTime();
    }

    private static DateTimeOffset? ReadX509TimeOpt(ref AsnReader reader)
    {
        if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime))
        {
            return reader.ReadUtcTime();
        }

        if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.GeneralizedTime))
        {
            return reader.ReadGeneralizedTime();
        }

        return null;
    }
}
