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
    private readonly object _crlNumberLock = new();
    private AsymmetricAlgorithm _privateKey = null!;
    private X509Certificate2Collection _certificateChain = [];
    private X509Certificate2Collection _publishedCertificateChain = [];

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
    /// Gets the certificates that should be published to EST clients.
    /// When empty, <see cref="CertificateChain"/> is published.
    /// </summary>
    public X509Certificate2Collection PublishedCertificateChain
    {
        get { return _publishedCertificateChain; }
        init { _publishedCertificateChain = value; }
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

        DisposeReplacedMaterials(currentPrivateKey, oldCertificates, oldPublishedCertificates);
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
        DisposeRemovedPublishedCertificates(oldPublishedCertificates, publishedCertificates);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        DisposeReplacedMaterials(PrivateKey, CertificateChain, PublishedCertificateChain);
        GC.SuppressFinalize(this);
    }

    private static void DisposeReplacedMaterials(
        AsymmetricAlgorithm privateKey,
        X509Certificate2Collection certificateChain,
        X509Certificate2Collection publishedCertificateChain)
    {
        privateKey.Dispose();
        foreach (var cert in certificateChain)
        {
            cert.Dispose();
        }

        foreach (var cert in publishedCertificateChain)
        {
            if (certificateChain.Any(existing => ReferenceEquals(existing, cert)))
            {
                continue;
            }

            cert.Dispose();
        }
    }

    private static void DisposeRemovedPublishedCertificates(
        X509Certificate2Collection oldPublishedCertificates,
        X509Certificate2Collection newPublishedCertificates)
    {
        foreach (var cert in oldPublishedCertificates)
        {
            if (newPublishedCertificates.Any(existing => ReferenceEquals(existing, cert)))
            {
                continue;
            }

            cert.Dispose();
        }
    }

    private static void AddUniqueCertificate(X509Certificate2Collection collection, X509Certificate2 certificate)
    {
        if (collection.Any(existing => string.Equals(existing.Thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)))
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
            throw new ArgumentException("The provided certificate does not match the provided private key.", nameof(privateKey));
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
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(
                ExportSubjectPublicKeyInfo(issuerCertificate)));

        var signatureGenerator = issuerPrivateKey switch
        {
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pss),
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

        throw new NotSupportedException($"Unsupported certificate public key algorithm '{certificate.PublicKey.Oid.Value}'.");
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
