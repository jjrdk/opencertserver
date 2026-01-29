namespace OpenCertServer.Ca.Utils;

using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509Extensions;

/// <summary>
/// Defines a Certificate Revocation List (CRL).
/// </summary>
public class CertificateRevocationList
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateRevocationList"/> class.
    /// </summary>
    /// <param name="version">The CRL format version.</param>
    /// <param name="signatureAlgorithm">The signature algorithm used.</param>
    /// <param name="issuer">The distinguished name of the CRL issuer.</param>
    /// <param name="thisUpdate">The <see cref="DateTimeOffset"/> when the CRL was issued.</param>
    /// <param name="nextUpdate">The <see cref="DateTimeOffset"/> when the next CRL will be issued.</param>
    /// <param name="revokedCertificates">The <see cref="List{T}"/> of revoked <see cref="RevokedCertificates"/>.</param>
    /// <param name="extensions">The CRL extensions.</param>
    /// <remarks>
    /// <para>
    /// If the <paramref name="extensions"/> is not null, it must contain a <see cref="X509CrlNumberExtension"/> which defines a positive CRL number.
    /// </para>
    /// </remarks>
    public CertificateRevocationList(
        CrlVersion version,
        HashAlgorithmName signatureAlgorithm,
        X500DistinguishedName issuer,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        IEnumerable<RevokedCertificate> revokedCertificates,
        IEnumerable<X509Extension>? extensions = null)
    {
        Extensions = extensions == null
            ? [new X509CrlNumberExtension(BigInteger.One, false)]
            : extensions.ToList().AsReadOnly();

        if (!Extensions.Any(e => e is X509CrlNumberExtension))
        {
            throw new ArgumentException("CRL extensions must include a CRL number extension.", nameof(extensions));
        }

        if (CrlNumber < 0)
        {
            throw new ArgumentException("CRL number must be non-negative.", nameof(extensions));
        }

        Version = version;
        SignatureAlgorithm = signatureAlgorithm;
        Issuer = issuer;
        ThisUpdate = thisUpdate;
        NextUpdate = nextUpdate;
        RevokedCertificates = revokedCertificates.ToList().AsReadOnly();
    }

    /// <summary>
    /// Gets the list of revoked certificates.
    /// </summary>
    public IReadOnlyCollection<RevokedCertificate> RevokedCertificates { get; set; }

    /// <summary>
    /// Gets the CRL version.
    /// </summary>
    public CrlVersion Version { get; }

    /// <summary>
    /// Gets the CRL number.
    /// </summary>
    public BigInteger CrlNumber
    {
        get { return Extensions.OfType<X509CrlNumberExtension>().FirstOrDefault()?.CrlNumber ?? BigInteger.Zero; }
    }

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

    public IReadOnlyCollection<X509Extension> Extensions { get; }

    /// <summary>
    /// Defines the CRL version.
    /// </summary>
    public enum CrlVersion
    {
        V1 = 0,
        V2 = 1,
        V3 = 2
    }

    public static CertificateRevocationList LoadPem(
        ReadOnlySpan<char> pemCrl,
        AsymmetricAlgorithm? issuerPublicKey = null)
    {
        pemCrl = pemCrl.Trim("-----BEGIN X509 CRL-----").Trim("-----END X509 CRL-----");
        var pemBytes = Convert.FromBase64String(pemCrl.ToString());
        return Load(pemBytes, issuerPublicKey);
    }

    public byte[] Build(HashAlgorithmName hashAlgorithmName, AsymmetricAlgorithm signingKey)
    {
        var tbsCertList = WriteTbsCertList();
        var hashAlgo = Oids.GetSignatureAlgorithmOid(hashAlgorithmName, signingKey);
        var signature = signingKey switch
        {
            RSA rsa => rsa.SignData(tbsCertList, hashAlgorithmName, RSASignaturePadding.Pss),
            ECDsa ecdsa => ecdsa.SignData(tbsCertList, hashAlgorithmName, DSASignatureFormat.Rfc3279DerSequence),
            _ => throw new NotSupportedException($"Signing key type {signingKey.GetType()} not supported.")
        };
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            // CertificateList
            writer.WriteEncodedValue(tbsCertList); // tbsCertList
            using (writer.PushSequence())
            {
                // signatureAlgorithm
                writer.WriteObjectIdentifier(hashAlgo);
            }

            writer.WriteBitString(signature);
        }

        return writer.Encode();
    }

    private byte[] WriteTbsCertList()
    {
        var tbsCertSequenceWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tbsCertSequenceWriter.PushSequence())
        {
            // TBSCertList
            tbsCertSequenceWriter.WriteInteger((int)Version); // version
            // Write algo identifier
            using (tbsCertSequenceWriter.PushSequence())
            {
                var hashAlgoOid = Oids.GetSignatureAlgorithmOid(SignatureAlgorithm, RSA.Create());
                tbsCertSequenceWriter.WriteObjectIdentifier(hashAlgoOid);
            }
            // Write Distinguished Name

            Issuer.Encode(tbsCertSequenceWriter);

            tbsCertSequenceWriter.WriteUtcTime(ThisUpdate);
            if (NextUpdate.HasValue)
            {
                tbsCertSequenceWriter.WriteUtcTime(NextUpdate.Value);
            }

            // revokedCertificates
            using (tbsCertSequenceWriter.PushSequence())
            {
                foreach (var revokedCertificate in RevokedCertificates)
                {
                    revokedCertificate.Encode(tbsCertSequenceWriter);
                }
            }

            // extensions
            if (Extensions.Count > 0)
            {
                using (tbsCertSequenceWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    using (tbsCertSequenceWriter.PushSequence())
                    {
                        foreach (var extension in Extensions)
                        {
                            extension.Encode(tbsCertSequenceWriter);
                        }
                    }
                }
            }
        }

        var tbsCertList = tbsCertSequenceWriter.Encode();
        return tbsCertList;
    }

    /// <summary>
    /// Reads and verifies a DER-encoded CRL using the issuer's public key.
    /// </summary>
    /// <param name="crl">The DER encoded certificate revocation list.</param>
    /// <param name="issuerPublicKey">The public key of the issuer.</param>
    /// <returns>A populated instance of a <see cref="CertificateRevocationList"/>.</returns>
    /// <exception cref="CryptographicException">Raised if the signature cannot be verified or the content is malformed.</exception>
    public static CertificateRevocationList Load(ReadOnlyMemory<byte> crl, AsymmetricAlgorithm? issuerPublicKey = null)
    {
        // CRL ::= SEQUENCE {
        //     tbsCertList             TBSCertList,
        //     signatureAlgorithm      AlgorithmIdentifier,
        //     signatureValue          BIT STRING
        // }

        var tbsSpan = issuerPublicKey == null ? ReadOnlySpan<byte>.Empty : ReadSignedContent(crl);

        var reader = new AsnReader(crl, AsnEncodingRules.DER);
        var certificateList = reader.ReadSequence();
        var tbsCertList = certificateList.ReadSequence();
        var algoIdentifier = certificateList.ReadSequence();
        reader.ThrowIfNotEmpty();
        var signature = certificateList.ReadBitString(out _, Asn1Tag.PrimitiveBitString);

        var signatureAlgo = algoIdentifier.ReadObjectIdentifier(Asn1Tag.ObjectIdentifier).GetHashAlgorithmFromOid();

        if (issuerPublicKey != null && !issuerPublicKey.VerifySignature(tbsSpan, signature, signatureAlgo))
        {
            throw new CryptographicException("CRL signature verification failed.");
        }

        var version = tbsCertList.ReadVersion();

        // Discard algorithm identifier as it is supposed to match the outer one
        _ = tbsCertList.ReadSequence();

        var distinguishedName = tbsCertList.ReadDistinguishedName();

        // thisUpdate
        var thisUpdate = tbsCertList.ReadX509Time();

        // nextUpdate
        var nextUpdate = tbsCertList.ReadOptionalX509Time();

        // revokedCertificates
        var list = tbsCertList.ReadRevokedCertificates(version);
        X509Extension[] crlExtensionList = [];
        if (version > 0 && tbsCertList.HasData)
        {
            var crlExtensionsExplicit =
                tbsCertList.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            var crlExtensions = crlExtensionsExplicit.ReadSequence();
            crlExtensionsExplicit.ThrowIfNotEmpty();

            crlExtensionList = [..crlExtensions.ReadCrlExtensions()];
        }

        tbsCertList.ThrowIfNotEmpty();

        return new CertificateRevocationList(
            (CrlVersion)version,
            signatureAlgo,
            distinguishedName,
            thisUpdate,
            nextUpdate,
            list,
            crlExtensionList);
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
        var hashAlgorithm = oid.GetHashAlgorithmFromOid();

        // 3. Read signatureValue (BIT STRING)
        var signatureValue = certificateList.ReadBitString(out var unusedBits, Asn1Tag.ConstructedBitString);
        if (unusedBits != 0)
            throw new CryptographicException("Signature BIT STRING has unused bits != 0");
        certificateList.ThrowIfNotEmpty();

        // Remove leading zero if present (some implementations add it)
        var signature = signatureValue.Length > 0 && signatureValue[0] == 0
            ? signatureValue.AsSpan(1).ToArray()
            : signatureValue;
        return issuerPublicKey.VerifySignature(tbsSpan, signature, hashAlgorithm);
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
}
