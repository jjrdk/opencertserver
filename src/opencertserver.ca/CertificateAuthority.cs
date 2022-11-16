namespace OpenCertServer.Ca
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text.RegularExpressions;
    using Microsoft.Extensions.Logging;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Pkcs;
    using Utils;
    using Cms = Org.BouncyCastle.Asn1.Cms;

    public sealed class CertificateAuthority : ICertificateAuthority, IDisposable
    {
        private const string Header = "-----BEGIN CERTIFICATE REQUEST-----";
        private const string Footer = "-----END CERTIFICATE REQUEST-----";

        private const X509KeyUsageFlags UsageFlags = X509KeyUsageFlags.CrlSign
                                                     | X509KeyUsageFlags.DataEncipherment
                                                     | X509KeyUsageFlags.DecipherOnly
                                                     | X509KeyUsageFlags.DigitalSignature
                                                     | X509KeyUsageFlags.EncipherOnly
                                                     | X509KeyUsageFlags.KeyAgreement
                                                     | X509KeyUsageFlags.KeyCertSign
                                                     | X509KeyUsageFlags.KeyEncipherment
                                                     | X509KeyUsageFlags.NonRepudiation;

        private readonly ILogger<CertificateAuthority> _logger;
        private readonly X509Certificate2 _rsaCertificate;
        private readonly X509Certificate2 _ecdsaCertificate;
        private readonly TimeSpan _certificateValidity;
        private readonly Func<X509Chain, bool> _x509ChainValidation;
        private readonly IValidateCertificateRequests[] _validators;
        private readonly bool _standAlone;

        public CertificateAuthority(
            X500DistinguishedName distinguishedName,
            TimeSpan certificateValidity,
            Func<X509Chain, bool> x509ChainValidation,
            ILogger<CertificateAuthority> logger,
            Action<X509Certificate2, X509Certificate2>? certificateBackup = null,
            params IValidateCertificateRequests[] validators)
            : this(
                CreateSelfSignedRsaCert(distinguishedName, UsageFlags, certificateValidity),
                CreateSelfSignedEcDsaCert(distinguishedName, UsageFlags, certificateValidity),
                certificateValidity,
                x509ChainValidation,
                logger,
                certificateBackup,
                validators)
        {
            _standAlone = true;
        }

        public CertificateAuthority(
            X509Certificate2 rsaCertificate,
            X509Certificate2 ecdsaCertificate,
            TimeSpan certificateValidity,
            Func<X509Chain, bool> x509ChainValidation,
            ILogger<CertificateAuthority> logger,
            Action<X509Certificate2, X509Certificate2>? certificateBackup = null,
            params IValidateCertificateRequests[] validators)
        {
            _logger = logger;
            _rsaCertificate = rsaCertificate;
            _ecdsaCertificate = ecdsaCertificate;
            _certificateValidity = certificateValidity;
            _x509ChainValidation = x509ChainValidation;
            _validators = validators.Concat(
                    new IValidateCertificateRequests[]
                    {
                        new OwnCertificateValidation(
                            new X509Certificate2Collection { _rsaCertificate, _ecdsaCertificate },
                            _logger),
                        new DistinguishedNameValidation()
                    })
                .ToArray();
            certificateBackup?.Invoke(_rsaCertificate, _ecdsaCertificate);
        }

        public SignCertificateResponse SignCertificateRequest(
            CertificateRequest request,
            X509Certificate2? reenrollingFrom = null)
        {
            if (!_validators.Aggregate(true, (b, v) => b && v.Validate(request)))
            {
                const string? error = "Could not validate request";
                _logger.LogError(error);
                return new SignCertificateResponse.Error(error);
            }

            _logger.LogInformation("Creating certificate for {subjectName}", request.SubjectName.Name);
            var cert = request.PublicKey.Oid.Value switch
            {
                CertificateConstants.RsaOid => request.Create(
                       _rsaCertificate,
                       DateTimeOffset.UtcNow.Date,
                       DateTimeOffset.UtcNow.Date.Add(_certificateValidity),
                       BitConverter.GetBytes(DateTime.UtcNow.Ticks)),
                CertificateConstants.EcdsaOid => request.Create(
                    _ecdsaCertificate,
                    DateTimeOffset.UtcNow.Date,
                    DateTimeOffset.UtcNow.Date.Add(_certificateValidity),
                    BitConverter.GetBytes(DateTime.UtcNow.Ticks)),
                _ => null
            };

            if (cert == null)
            {
                return new SignCertificateResponse.Error("Unsupported key algorithm");
            }

            using var chain = new X509Chain
            {
                ChainPolicy = new X509ChainPolicy
                {
                    VerificationFlags = X509VerificationFlags.IgnoreEndRevocationUnknown
                                        | X509VerificationFlags.AllowUnknownCertificateAuthority
                                        | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown,
                    RevocationFlag = X509RevocationFlag.ExcludeRoot
                }
            };

            chain.ChainPolicy.ExtraStore.Add(_rsaCertificate);
            chain.ChainPolicy.ExtraStore.Add(_ecdsaCertificate);

            var chainBuilt = _standAlone || chain.Build(cert);

            if (chainBuilt || _x509ChainValidation(chain))
            {
                return new SignCertificateResponse.Success(
                    cert,
                    new X509Certificate2Collection
                    {
                        request.PublicKey.Oid.Value switch
                        {
                            "1.2.840.113549.1.1.1" => _rsaCertificate,
                            "1.2.840.10045.2.1" => _ecdsaCertificate,
                            _ => throw new InvalidOperationException($"Invalid Oid: {request.PublicKey.Oid.Value}")
                        }
                    });
            }

            var errors = chain.ChainStatus.Select(
                    chainStatus => $"Certificate chain error: {chainStatus.Status} {chainStatus.StatusInformation}")
                .ToArray();
            _logger.LogError("{errors}", string.Join(";", errors));
            return new SignCertificateResponse.Error(errors);
        }

        public SignCertificateResponse SignCertificateRequest(string request)
        {
            request = request.Replace(Header, "", StringComparison.OrdinalIgnoreCase)
                .Replace(Footer, "", StringComparison.OrdinalIgnoreCase)
                .Trim();

            var bytes = Base64DecodeBytes(request);

            return SignCertificateRequest(bytes);
        }

        public SignCertificateResponse SignCertificateRequest(byte[] bytes)
        {
            var pkcs10Req = new Pkcs10CertificationRequest(bytes);
            var pub = pkcs10Req.GetPublicKey();
            var info = pkcs10Req.GetCertificationRequestInfo();
            var request = CreateCertificateRequest(pub, info);

            var o = (DerSequence)info.Attributes.Parser.ReadObject().ToAsn1Object();

            foreach (var extension in ResolveRecursive(o))
            {
                request.CertificateExtensions.Add(extension);
            }

            return SignCertificateRequest(request);
        }

        /// <inheritdoc />
        public X509Certificate2Collection GetRootCertificates()
        {
            return new X509Certificate2Collection { _rsaCertificate, _ecdsaCertificate };
        }

        private static CertificateRequest CreateCertificateRequest(
            AsymmetricKeyParameter pub,
            CertificationRequestInfo info)
        {
            switch (pub)
            {
                case RsaKeyParameters rsa:
                    {
                        var pk = RSA.Create(
                            new RSAParameters
                            {
                                Modulus = rsa.Modulus.ToByteArray(),
                                Exponent = rsa.Exponent.ToByteArray()
                            });
                        return new CertificateRequest(
                            info.Subject.ToString(),
                            pk,
                            HashAlgorithmName.SHA256,
                            RSASignaturePadding.Pss);
                    }
                case ECPublicKeyParameters ecp:
                    {
                        var ec = ECDsa.Create();
                        ec.ImportParameters(new ECParameters
                        {
                            Curve = ECCurve.CreateFromOid(new Oid(ecp.PublicKeyParamSet.Id)),
                            Q = new ECPoint
                            {
                                X = ecp.Q.XCoord.GetEncoded(),
                                Y = ecp.Q.YCoord.GetEncoded()
                            }
                        });

                        return new CertificateRequest(
                            info.Subject.ToString(),
                            ec,
                            HashAlgorithmName.SHA256);
                    }
                default:
                    throw new ArgumentException("Unknown argument", nameof(pub));
            }
        }

        private static X509Certificate2 CreateSelfSignedRsaCert(
            X500DistinguishedName distinguishedName,
            X509KeyUsageFlags usageFlags,
            TimeSpan certificateValidity)
        {
            using var parent = RSA.Create(4096);
            var parentReq = new CertificateRequest(
                distinguishedName,
                parent,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);

            return SelfSignCert(usageFlags, certificateValidity, parentReq);
        }

        private static X509Certificate2 CreateSelfSignedEcDsaCert(
            X500DistinguishedName distinguishedName,
            X509KeyUsageFlags usageFlags,
            TimeSpan certificateValidity)
        {
            using var parent = ECDsa.Create();
            var parentReq = new CertificateRequest(
                distinguishedName,
                parent,
                HashAlgorithmName.SHA256);

            return SelfSignCert(usageFlags, certificateValidity, parentReq);
        }

        private static X509Certificate2 SelfSignCert(
            X509KeyUsageFlags usageFlags,
            TimeSpan certificateValidity,
            CertificateRequest parentReq)
        {
            parentReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            parentReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));

            parentReq.CertificateExtensions.Add(new X509KeyUsageExtension(usageFlags, true));

            var parentCert = parentReq.CreateSelfSigned(
                DateTimeOffset.UtcNow.Date,
                DateTimeOffset.UtcNow.Date.Add(certificateValidity));

            return parentCert;
        }

        private static IEnumerable<X509Extension> ResolveRecursive(Asn1Sequence sequence)
        {
            var attr = new Cms.Attribute(sequence);
            foreach (var s in attr.AttrValues.OfType<DerSequence>())
            {
                foreach (var s2 in s.OfType<DerSequence>())
                {
                    var derOid = s2.OfType<DerObjectIdentifier>().First();
                    var octetString = s2.OfType<DerOctetString>().First();
                    var derBool = s2.OfType<DerBoolean>().FirstOrDefault();
                    var critical = derBool?.IsTrue == true;
                    var oid = Oid.FromOidValue(derOid.Id, OidGroup.All);
                    var data = new AsnEncodedData(octetString.GetOctets());
                    yield return derOid.Id switch
                    {
                        "2.5.29.14" => new X509SubjectKeyIdentifierExtension(data, critical),
                        "2.5.29.15" => new X509KeyUsageExtension(data, critical),
                        "2.5.29.19" => new X509BasicConstraintsExtension(data, critical),
                        "2.5.29.37" => new X509EnhancedKeyUsageExtension(data, critical),
                        _ => new X509Extension(oid, octetString.GetOctets(), critical)
                    };
                }
            }
        }

        public void Dispose()
        {
            _rsaCertificate.Dispose();
            _ecdsaCertificate.Dispose();
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Base64 decode.
        /// </summary>
        /// <param name="base64EncodedData">The base64 encoded data.</param>
        /// <returns></returns>
        private static byte[] Base64DecodeBytes(string base64EncodedData)
        {
            var s = base64EncodedData
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
        private sealed class OwnCertificateValidation : IValidateCertificateRequests
        {
            private readonly X509Certificate2Collection _serverCertificates;
            private readonly ILogger _logger;

            public OwnCertificateValidation(X509Certificate2Collection serverCertificates, ILogger logger)
            {
                _serverCertificates = serverCertificates;
                _logger = logger;
            }

            public bool Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null)
            {
                var result = reenrollingFrom == null
                             || _serverCertificates
                                 .Aggregate(false, (b, cert) => b || reenrollingFrom.IssuerName.Name == cert.SubjectName.Name);
                if (!result)
                {
                    _logger.LogError("Could not validate re-enrollment from {reenrollingFrom}", reenrollingFrom!.IssuerName.Name);
                }

                return result;
            }
        }

        private sealed class DistinguishedNameValidation : IValidateCertificateRequests
        {
            public bool Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null)
            {
                return request.SubjectName.Format(true)
                    .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                    .Any(x => x.StartsWith("CN="));
            }
        }
    }
}
