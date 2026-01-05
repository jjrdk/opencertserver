using System.Collections.ObjectModel;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils;

public class CertificateRevocationList
{
    public CertificateRevocationList(
        CrlVersion version,
        BigInteger crlNumber,
        string signatureAlgorithm,
        X500DistinguishedName issuer,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate,
        IEnumerable<RevokedCertificate> revokedCertificates)
    {
        Version = version;
        CrlNumber = crlNumber;
        SignatureAlgorithm = signatureAlgorithm;
        Issuer = issuer;
        ThisUpdate = thisUpdate;
        NextUpdate = nextUpdate;
        RevokedCertificates = revokedCertificates.ToList().AsReadOnly();
    }

    public ReadOnlyCollection<RevokedCertificate> RevokedCertificates { get; set; }
    public CrlVersion Version { get; }
    public BigInteger CrlNumber { get; }
    public string SignatureAlgorithm { get; }
    public X500DistinguishedName Issuer { get; }
    public DateTimeOffset ThisUpdate { get; }
    public DateTimeOffset? NextUpdate { get; }

    public enum CrlVersion
    {
        V1 = 0,
        V2 = 1
    }

    public static CertificateRevocationList Load(ReadOnlySpan<byte> currentCrl)
    {
        BigInteger crlNumber = 0;

        try
        {
            var reader = new AsnValueReader(currentCrl, AsnEncodingRules.DER);

            var certificateList = reader.ReadSequence();
            var tbsCertList = certificateList.ReadSequence();

            var version = ReadVersion(ref tbsCertList);

            var algoAsn = ReadAlgorithmIdentifierAsn(ref tbsCertList);
            var distinguishedName = ReadDistinguishedName(ref tbsCertList);

            // thisUpdate
            var thisUpdate = ReadX509Time(ref tbsCertList);

            // nextUpdate
            var nextUpdate = ReadX509TimeOpt(ref tbsCertList);

            AsnValueReader revokedCertificates = default;

            if (tbsCertList.HasData && tbsCertList.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                revokedCertificates = tbsCertList.ReadSequence();
            }

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

            var list = ReadRevokedCertificates(revokedCertificates, version);

            return new CertificateRevocationList(
                (CrlVersion)version,
                crlNumber,
                algoAsn.Algorithm,
                distinguishedName,
                thisUpdate,
                nextUpdate,
                list);
        }
        catch (AsnContentException e)
        {
            throw new CryptographicException("Invalid DER encoding.", e);
        }
    }

    private static int ReadVersion(ref AsnValueReader tbsCertList)
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

    private static AlgorithmIdentifierAsn ReadAlgorithmIdentifierAsn(ref AsnValueReader tbsCertList)
    {
        AlgorithmIdentifierAsn.Decode(ref tbsCertList, ReadOnlyMemory<byte>.Empty, out var algoAsn);
        return algoAsn;
    }

    private static X500DistinguishedName ReadDistinguishedName(ref AsnValueReader tbsCertList)
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

    private static List<RevokedCertificate> ReadRevokedCertificates(AsnValueReader revokedCertificates, int version)
    {
        List<RevokedCertificate> list = [];
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

    private static DateTimeOffset ReadX509Time(ref AsnValueReader reader)
    {
        return reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime)
            ? reader.ReadUtcTime()
            : reader.ReadGeneralizedTime();
    }

    private static DateTimeOffset? ReadX509TimeOpt(ref AsnValueReader reader)
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
