namespace OpenCertServer.Ca.Utils.Ca;

using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Defines a CA profile with private key, certificate chain, and other properties.
/// </summary>
public record CaProfile : IDisposable
{
    private BigInteger _crlNumber;
    private readonly Lock _crlNumberLock = new();
    private AsymmetricAlgorithm _privateKey = null!;
    private X509Certificate2Collection _certificateChain = [];
    private X509Certificate2Collection _publishedCertificateChain = [];
    private X509Certificate2Collection _trustAnchors = [];
    private X509Certificate2Collection _additionalChainCertificates = [];

    /// <summary>
    /// Gets or sets the name of the CA profile.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Gets the private key associated with the CA profile.
    /// </summary>
    public required AsymmetricAlgorithm PrivateKey
    {
        get { return _privateKey; }
        init { _privateKey = value; }
    }

    /// <summary>
    /// Gets the certificate chain associated with the CA profile.
    /// </summary>
    public required X509Certificate2Collection CertificateChain
    {
        get { return _certificateChain; }
        init { _certificateChain = value; }
    }

    /// <summary>
    /// Gets additional certificates to publish to EST clients, including rollover certificates.
    /// The issuing <see cref="CertificateChain"/> is always published (RFC 7030 section 4.1.3).
    /// </summary>
    public X509Certificate2Collection PublishedCertificateChain
    {
        get { return _publishedCertificateChain; }
        init { _publishedCertificateChain = value; }
    }

    /// <summary>
    /// Gets additional explicit roots for EST client authentication against this profile (RFC 7030 section 3.3.2).
    /// These do not replace the issuing chain and are not published by /cacerts.
    /// </summary>
    public X509Certificate2Collection TrustAnchors
    {
        get { return _trustAnchors; }
        init
        {
            foreach (var certificate in value)
            {
                certificate.ValidateCertificateAuthority();
            }

            _trustAnchors = value;
        }
    }

    /// <summary>
    /// Gets CA certificates used only to build EST client authentication chains for this profile.
    /// These certificates do not independently establish trust and are not published by /cacerts.
    /// </summary>
    public X509Certificate2Collection AdditionalChainCertificates
    {
        get { return _additionalChainCertificates; }
        init
        {
            foreach (var certificate in value)
            {
                certificate.ValidateCertificateAuthority();
            }

            _additionalChainCertificates = value;
        }
    }

    /// <summary>
    /// Gets the validity period for certificates issued by this CA profile.
    /// </summary>
    public TimeSpan CertificateValidity { get; init; }

    /// <summary>
    /// Gets or sets the CRL number for the CA profile.
    /// </summary>
    public BigInteger CrlNumber
    {
        get { return _crlNumber; }
        init { _crlNumber = value; }
    }

    /// <summary>
    /// Gets the next CRL number for the CA profile.
    /// </summary>
    /// <returns>The next CRL number</returns>
    public BigInteger GetNextCrlNumber()
    {
        lock (_crlNumberLock)
        {
            _crlNumber += BigInteger.One;
            return _crlNumber;
        }
    }

    /// <summary>
    /// Rolls the profile over to a new active CA certificate and private key.
    /// The current certificate becomes the rollover origin and the EST-published bundle is updated to include
    /// the new active certificate together with the OldWithOld, OldWithNew, and NewWithOld rollover certificates.
    /// </summary>
    /// <param name="certificate">The new active CA certificate.</param>
    /// <param name="privateKey">The private key that corresponds to <paramref name="certificate"/>.</param>
    /// <exception cref="ArgumentNullException">Thrown when a required argument is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the profile has no current CA certificate to roll over.</exception>
    /// <exception cref="ArgumentException">Thrown when the provided certificate and key do not match or the certificate is not a CA certificate.</exception>
    public void RollOver(X509Certificate2 certificate, AsymmetricAlgorithm privateKey)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(privateKey);

        if (CertificateChain.Count == 0)
        {
            throw new InvalidOperationException("The CA profile does not contain a current certificate to roll over.");
        }

        EnsureCertificateMatchesPrivateKey(certificate, privateKey);

        var currentCertificate = CertificateChain[0];
        var currentPrivateKey = PrivateKey;
        var oldCertificates = CertificateChain;
        var oldPublishedCertificates = PublishedCertificateChain;
        var newActiveCertificate = ClonePublicCertificate(certificate);
        var rolloverCertificates = new X509Certificate2Collection
        {
            newActiveCertificate,
            ClonePublicCertificate(currentCertificate),
            CreateCrossSignedCaCertificate(currentCertificate, currentPrivateKey, certificate, privateKey),
            CreateCrossSignedCaCertificate(certificate, privateKey, currentCertificate, currentPrivateKey)
        };

        _privateKey = privateKey;
        _certificateChain = [newActiveCertificate];
        _publishedCertificateChain = rolloverCertificates;

        DisposeReplacedMaterials(currentPrivateKey, oldCertificates, oldPublishedCertificates,
            TrustAnchors.Concat(AdditionalChainCertificates));
    }

    /// <summary>
    /// Closes the rollover publication window and returns the published CA bundle to the active certificate chain only.
    /// Any rollover-only certificates that were kept in <see cref="PublishedCertificateChain"/> are removed.
    /// </summary>
    public void CloseRolloverWindow()
    {
        var oldPublishedCertificates = PublishedCertificateChain;
        X509Certificate2Collection publishedCertificates = [];
        foreach (var certificate in CertificateChain)
        {
            AddUniqueCertificate(publishedCertificates, certificate);
        }

        _publishedCertificateChain = publishedCertificates;
        DisposeRemovedPublishedCertificates(oldPublishedCertificates,
            new X509Certificate2Collection(publishedCertificates.Concat(TrustAnchors)
                .Concat(AdditionalChainCertificates).ToArray()));
    }

    /// <inheritdoc />
    public void Dispose()
    {
        DisposeReplacedMaterials(PrivateKey,
            new X509Certificate2Collection(CertificateChain.Concat(TrustAnchors)
                .Concat(AdditionalChainCertificates).ToArray()), PublishedCertificateChain);
        GC.SuppressFinalize(this);
    }

    private static void DisposeReplacedMaterials(
        AsymmetricAlgorithm privateKey,
        X509Certificate2Collection certificateChain,
        X509Certificate2Collection publishedCertificateChain,
        IEnumerable<X509Certificate2>? retainedCertificates = null)
    {
        privateKey.Dispose();
        var retained = new HashSet<X509Certificate2>(retainedCertificates ?? [], ReferenceEqualityComparer.Instance);
        foreach (var cert in certificateChain.Concat(publishedCertificateChain)
            .Distinct<X509Certificate2>(ReferenceEqualityComparer.Instance)
            .Where(cert => !retained.Contains(cert)))
        {
            cert.Dispose();
        }
    }

    private static void DisposeRemovedPublishedCertificates(
        X509Certificate2Collection oldPublishedCertificates,
        X509Certificate2Collection newPublishedCertificates)
    {
        var newSet = new HashSet<X509Certificate2>(newPublishedCertificates, ReferenceEqualityComparer.Instance);
        foreach (var cert in oldPublishedCertificates.Where(cert => !newSet.Contains(cert)))
        {
            cert.Dispose();
        }
    }

    private static void AddUniqueCertificate(X509Certificate2Collection collection, X509Certificate2 certificate)
    {
        if (collection.Any(existing =>
            string.Equals(existing.Thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        collection.Add(certificate);
    }

    private static void EnsureCertificateMatchesPrivateKey(X509Certificate2 certificate, AsymmetricAlgorithm privateKey)
    {
        var certificatePublicKey = ExportSubjectPublicKeyInfo(certificate);
        var privateKeyPublicKey = ExportSubjectPublicKeyInfo(privateKey);
        if (!certificatePublicKey.AsSpan().SequenceEqual(privateKeyPublicKey))
        {
            throw new ArgumentException("The provided certificate does not match the provided private key.",
                nameof(privateKey));
        }

        var basicConstraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        if (basicConstraints is not { CertificateAuthority: true })
        {
            throw new ArgumentException("The provided certificate must be a CA certificate.", nameof(certificate));
        }
    }

    private static X509Certificate2 CreateCrossSignedCaCertificate(
        X509Certificate2 subjectCertificate,
        AsymmetricAlgorithm subjectPrivateKey,
        X509Certificate2 issuerCertificate,
        AsymmetricAlgorithm issuerPrivateKey)
    {
        var request = CreateCaCertificateRequest(subjectCertificate, subjectPrivateKey);
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                issuerCertificate,
                includeKeyIdentifier: true,
                includeIssuerAndSerial: false));

        var signatureGenerator = issuerPrivateKey switch
        {
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            _ => throw new NotSupportedException()
        };

        return request.Create(
            issuerCertificate.SubjectName,
            signatureGenerator,
            subjectCertificate.NotBefore,
            subjectCertificate.NotAfter,
            RandomNumberGenerator.GetBytes(16));
    }

    private static CertificateRequest CreateCaCertificateRequest(
        X509Certificate2 certificate,
        AsymmetricAlgorithm privateKey)
    {
        var request = privateKey switch
        {
            RSA rsa => new CertificateRequest(
                certificate.SubjectName,
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss),
            ECDsa ecdsa => new CertificateRequest(certificate.SubjectName, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException()
        };

        var basicConstraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        request.CertificateExtensions.Add(basicConstraints == null
            ? new X509BasicConstraintsExtension(true, false, 0, true)
            : new X509BasicConstraintsExtension(
                basicConstraints.CertificateAuthority,
                basicConstraints.HasPathLengthConstraint,
                basicConstraints.PathLengthConstraint,
                basicConstraints.Critical));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        request.CertificateExtensions.Add(keyUsage == null
            ? new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true)
            : new X509KeyUsageExtension(keyUsage.KeyUsages, keyUsage.Critical));
        return request;
    }

    private static X509Certificate2 ClonePublicCertificate(X509Certificate2 certificate)
    {
        return X509Certificate2.CreateFromPem(certificate.ExportCertificatePem());
    }

    private static byte[] ExportSubjectPublicKeyInfo(X509Certificate2 certificate)
    {
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa != null)
        {
            return rsa.ExportSubjectPublicKeyInfo();
        }

        using var ecdsa = certificate.GetECDsaPublicKey();
        if (ecdsa != null)
        {
            return ecdsa.ExportSubjectPublicKeyInfo();
        }

        throw new NotSupportedException(
            $"Unsupported certificate public key algorithm '{certificate.PublicKey.Oid.Value}'.");
    }

    private static byte[] ExportSubjectPublicKeyInfo(AsymmetricAlgorithm privateKey)
    {
        return privateKey switch
        {
            RSA rsa => rsa.ExportSubjectPublicKeyInfo(),
            ECDsa ecdsa => ecdsa.ExportSubjectPublicKeyInfo(),
            _ => throw new NotSupportedException($"Unsupported private key algorithm '{privateKey.GetType().Name}'.")
        };
    }

    /// <summary>
    /// Gets the OIDs of CSR extensions that are permitted to be copied into issued certificates.
    /// Extensions present in the CSR but whose OID is not in this list are silently discarded.
    /// The default set permits safe leaf-certificate extensions: SAN, EKU, and keyUsage.
    /// </summary>
    /// <remarks>
    /// Dangerous CA-structural extensions are blocked by default. To allow a profile to issue
    /// intermediate CA certificates, add <c>2.5.29.19</c> (basicConstraints) to this list;
    /// <c>2.5.29.15</c> (keyUsage) is already in the default and permits keyCertSign/cRLSign
    /// only when 2.5.29.19 is also present.
    /// Server-managed extensions (SKI 2.5.29.14, AKI 2.5.29.35, AIA 1.3.6.1.5.5.7.1.1,
    /// CRLDP 2.5.29.31) are always regenerated by the server and are stripped from the CSR
    /// regardless of this list, and so are certificate policies (2.5.29.32): a policy is the
    /// CA's assertion, never the requester's - see <see cref="CertificatePolicies"/>.
    /// </remarks>
    public IReadOnlyList<string> AllowedCsrExtensions { get; init; } =
    [
        Oids.SubjectAltName,
        Oids.EnhancedKeyUsage,
        Oids.KeyUsage,
    ];

    /// <summary>
    /// Gets the certificate policy identifiers (RFC 5280 §4.2.1.4) the CA writes into every
    /// certificate it issues from this profile. Empty by default: no certificatePolicies
    /// extension is written. Policies requested in a CSR are never taken over.
    /// </summary>
    /// <remarks>
    /// A relying party that requires a policy (strongSwan's <c>cert_policy</c>, Windows
    /// application policies) needs the issuing CA to assert it; a requester cannot claim it. A
    /// profile that issues intermediate CA certificates (2.5.29.19 in
    /// <see cref="AllowedCsrExtensions"/>) typically asserts <c>2.5.29.32.0</c> (anyPolicy) so
    /// the leaf policies below it validate.
    /// </remarks>
    public IReadOnlyList<string> CertificatePolicies { get; init; } = [];

    /// <summary>
    /// Gets the key usage (RFC 5280 §4.2.1.3) of every certificate issued from this profile.
    /// When set, it replaces whatever the CSR requested and is marked critical. When not set
    /// (the default), the CSR's key usage is taken over subject to <see cref="AllowedCsrExtensions"/>.
    /// </summary>
    public X509KeyUsageFlags? KeyUsage { get; init; }

    /// <summary>
    /// Gets the extended key usages (RFC 5280 §4.2.1.12, OIDs) of every certificate issued from
    /// this profile. When set, they replace whatever the CSR requested; an empty list means no
    /// extendedKeyUsage extension at all. When not set (the default), the CSR's extended key usage
    /// is taken over subject to <see cref="AllowedCsrExtensions"/>.
    /// </summary>
    public IReadOnlyList<string>? ExtendedKeyUsages { get; init; }

    /// <summary>
    /// Gets the OCSP freshness window for responses issued by this CA profile.
    /// </summary>
    public TimeSpan OcspFreshnessWindow { get; init; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets the OCSP signing certificate for delegated OCSP responses.
    /// When set, this certificate is used to sign OCSP responses instead of the CA certificate.
    /// </summary>
    public X509Certificate2? OcspSigningCertificate { get; init; }

    /// <summary>
    /// Gets the private key for the OCSP signing certificate.
    /// </summary>
    public AsymmetricAlgorithm? OcspSigningKey { get; init; }
}
