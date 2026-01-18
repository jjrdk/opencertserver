using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;
using OpenCertServer.Ca.Utils.X509Extensions;

namespace OpenCertServer.Ca.Utils;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

public static class EncodingExtensions
{
    extension(string value)
    {
        /// <summary>
        /// Base64 decode.
        /// </summary>
        /// <param name="base64EncodedData">The base64 encoded data.</param>
        /// <returns></returns>
        public byte[] Base64DecodeBytes()
        {
            var s = value
                .Replace(" ", "+")
                .Replace('-', '+')
                .Replace('_', '/')
                .Replace("\n", "")
                .Replace("\r", "")
                .Trim();
            switch (s.Length % 4)
            {
                case 0:
                    return Convert.FromBase64String(s);
                case 2:
                    s += "==";
                    goto case 0;
                case 3:
                    s += "=";
                    goto case 0;
                default:
                    throw new InvalidOperationException("Illegal base64url string!");
            }
        }

        public HashAlgorithmName GetHashAlgorithmFromOid()
        {
            return value switch
            {
                "1.2.840.113549.1.1.10" => HashAlgorithmName.SHA256, // rsassaPss
                "1.2.840.113549.1.1.11" => HashAlgorithmName.SHA256, // sha256WithRSAEncryption
                "1.2.840.113549.1.1.12" => HashAlgorithmName.SHA384,
                "1.2.840.113549.1.1.13" => HashAlgorithmName.SHA512,
                "1.2.840.113549.1.1.5" => HashAlgorithmName.SHA1, // sha1WithRSAEncryption
                "1.2.840.10045.4.3.2" => HashAlgorithmName.SHA256, // ecdsa-with-SHA256
                "1.2.840.10045.4.3.3" => HashAlgorithmName.SHA384,
                "1.2.840.10045.4.3.4" => HashAlgorithmName.SHA512,
                "1.2.840.10045.4.1" => HashAlgorithmName.SHA1, // ecdsa-with-SHA1
                _ => throw new CryptographicException($"Unsupported signature algorithm OID: {value}")
            };
        }

        public Oid InitializeOid()
        {
            var oid = new Oid(value, null);

            // Do not remove - the FriendlyName property get has side effects.
            // On read, it initializes the friendly name based on the value and
            // locks it to prevent any further changes.
            _ = oid.FriendlyName;

            return oid;
        }
    }

    extension(X500DistinguishedName distinguishedName)
    {
        public void Encode(AsnWriter writer)
        {
            using (writer.PushSequence())
            {
                foreach (var relativeDistinguishedName in
                    distinguishedName.EnumerateRelativeDistinguishedNames())
                {
                    using (writer.PushSetOf())
                    {
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(relativeDistinguishedName.GetSingleElementType()
                                .Value!);
                            writer.WriteCharacterString(
                                UniversalTagNumber.PrintableString,
                                relativeDistinguishedName.GetSingleElementValue()!);
                        }
                    }
                }
            }
        }
    }

    extension(X509Extension extension)
    {
        public void Encode(AsnWriter writer, Asn1Tag? tag = null)
        {
            using (writer.PushSequence(tag))
            {
                writer.WriteObjectIdentifier(extension.Oid!.Value!);
                if (extension.Critical)
                {
                    writer.WriteBoolean(extension.Critical);
                }

                writer.WriteOctetString(extension.RawData);
            }
        }
    }

    extension(AsnReader reader)
    {
        public Oid GetSharedOrNewOid()
        {
            var ret = reader.GetSharedOrNullOid();

            if (ret is not null)
            {
                return ret;
            }

            var oidValue = reader.ReadObjectIdentifier();
            return new Oid(oidValue, null);
        }

        public Oid? GetSharedOrNullOid(Asn1Tag? expectedTag = null)
        {
            var tag = reader.PeekTag();

            // This isn't a valid OID, so return null and let whatever's going to happen happen.
            if (tag.IsConstructed)
            {
                return null;
            }

            var expected = expectedTag.GetValueOrDefault(Asn1Tag.ObjectIdentifier);

            // Not the tag we're expecting, so don't match.
            if (!tag.HasSameClassAndValue(expected))
            {
                return null;
            }

            var contentBytes = reader.PeekContentBytes().Span;

            var ret = contentBytes switch
            {
                [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01] => Oids.EmailAddressOid,
                [0x55, 0x04, 0x03] => Oids.CommonNameOid,
                [0x55, 0x04, 0x06] => Oids.CountryOrRegionNameOid,
                [0x55, 0x04, 0x07] => Oids.LocalityNameOid,
                [0x55, 0x04, 0x08] => Oids.StateOrProvinceNameOid,
                [0x55, 0x04, 0x0A] => Oids.OrganizationOid,
                [0x55, 0x04, 0x0B] => Oids.OrganizationalUnitOid,
                [0x55, 0x1D, 0x14] => Oids.CrlNumberOid,
                _ => null,
            };

            if (ret is not null)
            {
                // Move to the next item.
                reader.ReadEncodedValue();
            }

            return ret;
        }

        public int ReadVersion()
        {
            var version = 0;

            if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
            {
                // https://datatracker.ietf.org/doc/html/rfc5280#section-5.1 says the only
                // version values are v1 (0) and v2 (1).
                //
                // Since v1 (0) is supposed to not write down the version value, v2 (1) is the
                // only legal value to read.
                if (!reader.TryReadInt32(out version) || version != 1)
                {
                    throw new CryptographicException("Invalid CRL version.");
                }
            }

            return version;
        }

        public List<RevokedCertificate> ReadRevokedCertificates(int version)
        {
            List<RevokedCertificate> list = [];
            if (!reader.HasData || !reader.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                return list;
            }

            var revokedCertificates = reader.ReadSequence();

            while (revokedCertificates.HasData)
            {
                var valueReader = revokedCertificates.ReadSequence();
                var serial = valueReader.ReadIntegerBytes().ToArray();
                var revocationTime = valueReader.ReadX509Time();
                CertificateExtension[] extensions = [];

                if (version > 0 && valueReader.HasData)
                {
                    var peekTag = valueReader.PeekTag();
                    if (!peekTag.HasSameClassAndValue(Asn1Tag.Sequence))
                    {
                        throw new CryptographicException("Invalid DER encoding for revoked certificate extensions.");
                    }

                    extensions =
                        valueReader.ReadCertificateExtensions().ToArray(); //valueReader.ReadEncodedValue().ToArray();
                }

                var revokedCertificate =
                    new RevokedCertificate(serial, revocationTime, extensions);
                list.Add(revokedCertificate);
            }

            return list;
        }

        public IEnumerable<CertificateExtension> ReadCertificateExtensions()
        {
            var extensions = reader.ReadSequence();
            while (extensions.HasData)
            {
                var certificateExtension = CertificateExtension.Decode(extensions);
                yield return certificateExtension;
            }
        }

        public X500DistinguishedName ReadDistinguishedName()
        {
            // X500DN
            var distinguishedName = new X500DistinguishedNameBuilder();
            var issuerSequence = reader.ReadSequence();
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

        public DateTimeOffset ReadX509Time()
        {
            return reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime)
                ? reader.ReadUtcTime()
                : reader.ReadGeneralizedTime();
        }

        public DateTimeOffset? ReadOptionalX509Time()
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

        public IEnumerable<X509Extension> ReadCrlExtensions()
        {
            while (reader.HasData)
            {
                yield return reader.DecodeExtension();
            }
        }

        public X509Extension DecodeExtension()
        {
            var extensionSeq = reader.ReadSequence();
            var isCritical = false;
            var extnOid = new Oid(extensionSeq.ReadObjectIdentifier());

            if (extensionSeq.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
            {
                isCritical = extensionSeq.ReadBoolean();
            }

            if (!extensionSeq.TryReadPrimitiveOctetString(out var extnValue))
            {
                throw new CryptographicException("Invalid DER encoding for CRL extension value.");
            }

            switch (extnOid.Value)
            {
                case "1.3.6.1.5.5.7.1.1": // Authority Information Access
                    return new X509AuthorityInformationAccessExtension(extnValue.Span, isCritical);
                case "2.5.29.35": // Authority Key Identifier
                    return new X509AuthorityKeyIdentifierExtension(extnValue.Span, isCritical);
                case "2.5.29.20": // CRL Number
                {
                    return new X509CrlNumberExtension(extnValue.Span, isCritical);
                }
                case "2.5.29.27": // Delta CRL Indicator
                {
                    return new X509DeltaCrlIndicatorExtension(extnValue.Span, isCritical);
                }
                case "2.5.29.46": // Freshest CRL
                    return new X509FreshestCrlExtension(extnValue.Span, isCritical);
//                    case "2.5.29.18": // Issuer Alternative Name
//                        crlExtensionList.Add(new X509IssuerAltNameExtension(extnValue.Span, isCritical));
//                        break;
                case "2.5.29.28": // Issuing Distribution Point
                    var distReader = new AsnReader(extnValue, AsnEncodingRules.DER);
                    var distributionPoint = new DistributionPoint(distReader.ReadSequence());
                    if (distributionPoint.DistributionPointName?.FullName?.Names.Length > 0)
                    {
                        return CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(
                            distributionPoint.DistributionPointName!.FullName!.Names.Select(gn =>
                                gn.Value.ToString()!), isCritical);
                    }

                    break;
                default:
                    return new X509RawExtension(extnOid, isCritical, extnValue.ToArray());
            }

            throw new CryptographicException("Unsupported CRL extension.");
        }
    }
}
