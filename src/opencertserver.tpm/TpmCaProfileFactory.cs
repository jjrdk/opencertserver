namespace OpenCertServer.Tpm;

using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// Bootstraps TPM-backed <see cref="CaProfile"/> instances.
/// <para>
/// On first run it provisions the TPM keys and self-signs the CA certificate.
/// On subsequent runs it loads the existing certificate from the OS certificate store
/// and wraps the persistent TPM handles — no key material ever leaves the TPM.
/// </para>
/// </summary>
public sealed class TpmCaProfileFactory : IDisposable
{
    private static readonly X509KeyUsageFlags CaUsageFlags =
        X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign;

    private readonly TpmCaOptions _options;
    private readonly ITpmKeyProvider _keyProvider;
    private readonly TpmCaCertificateStore _certStore;
    private readonly bool _ownsKeyProvider;

    /// <summary>
    /// Creates a factory using the supplied options and the default
    /// <see cref="TssTpmKeyProvider"/> as the TPM communication backend.
    /// </summary>
    public TpmCaProfileFactory(TpmCaOptions options)
        : this(options, new TssTpmKeyProvider(options), ownsKeyProvider: true) { }

    /// <summary>
    /// Creates a factory with a custom <see cref="ITpmKeyProvider"/> (e.g. a simulator
    /// or a Pkcs11Interop-based replacement).
    /// </summary>
    /// <param name="options">CA configuration.</param>
    /// <param name="keyProvider">The TPM key provider to use.</param>
    /// <param name="ownsKeyProvider">
    /// When <see langword="true"/> (default) the factory disposes <paramref name="keyProvider"/>
    /// when it is itself disposed.  Pass <see langword="false"/> when the provider is shared
    /// between multiple factory instances (e.g. during key rollover) so that the first factory
    /// to be disposed does not invalidate the shared connection.
    /// </param>
    public TpmCaProfileFactory(TpmCaOptions options, ITpmKeyProvider keyProvider,
                                bool ownsKeyProvider = true)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _keyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
        _certStore = new TpmCaCertificateStore(options.CertStoreName, options.CertStoreLocation);
        _ownsKeyProvider = ownsKeyProvider;
    }

    /// <summary>
    /// Creates (or loads) an RSA CA profile backed by the TPM key at
    /// <see cref="TpmCaOptions.RsaKeyHandle"/>.
    /// </summary>
    public CaProfile CreateOrLoadRsaProfile(string profileName)
    {
        _keyProvider.EnsureRsaKey(_options.RsaKeyHandle);
        var tpmRsa = new TpmRsa(_keyProvider, _options.RsaKeyHandle);

        var cert = LoadOrCreateCert(profileName, tpmRsa);
        var published = CreateInitialPublishedChain(cert);

        return new CaProfile
        {
            Name = profileName,
            PrivateKey = tpmRsa,
            CertificateChain = [cert],
            PublishedCertificateChain = published,
            CertificateValidity = _options.IssuedCertificateValidity,
            CrlNumber = BigInteger.Zero,
            OcspFreshnessWindow = _options.OcspFreshnessWindow
        };
    }

    /// <summary>
    /// Creates (or loads) an ECDsa CA profile backed by the TPM key at
    /// <see cref="TpmCaOptions.EcDsaKeyHandle"/>.
    /// </summary>
    public CaProfile CreateOrLoadEcDsaProfile(string profileName)
    {
        _keyProvider.EnsureEcDsaKey(_options.EcDsaKeyHandle);
        var tpmEcDsa = new TpmEcDsa(_keyProvider, _options.EcDsaKeyHandle);

        var cert = LoadOrCreateCert(profileName, tpmEcDsa);
        var published = CreateInitialPublishedChain(cert);

        return new CaProfile
        {
            Name = profileName,
            PrivateKey = tpmEcDsa,
            CertificateChain = [cert],
            PublishedCertificateChain = published,
            CertificateValidity = _options.IssuedCertificateValidity,
            CrlNumber = BigInteger.Zero,
            OcspFreshnessWindow = _options.OcspFreshnessWindow
        };
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsKeyProvider)
            _keyProvider.Dispose();
    }

    // -----------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------

    private X509Certificate2 LoadOrCreateCert(string profileName, AsymmetricAlgorithm key)
    {
        var existing = _certStore.LoadCertificate(profileName);
        if (existing != null)
        {
            return existing;
        }

        var cert = SelfSignCaCertificate(key);
        _certStore.StoreCertificate(profileName, cert);
        return cert;
    }

    private X509Certificate2 SelfSignCaCertificate(AsymmetricAlgorithm key)
    {
        var dn = new X500DistinguishedName(_options.CaSubjectName);
        var notBefore = DateTimeOffset.UtcNow.Date;
        var notAfter = notBefore.Add(_options.CaCertificateValidity);

        CertificateRequest request = key switch
        {
            RSA rsa => new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            ECDsa ecdsa => new CertificateRequest(dn, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException($"Unsupported key type '{key.GetType().Name}'.")
        };

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(CaUsageFlags, true));

        // Do NOT use CreateSelfSigned: on macOS (AppleCertificatePal) it calls CopyWithPrivateKey
        // → ExportRSAPrivateKey / ExportECPrivateKey → ExportParameters(true), which TPM-backed
        // keys intentionally refuse.  Instead, sign the TBS bytes via X509SignatureGenerator which
        // calls SignHash — the only signing path our TPM wrappers support.
        X509SignatureGenerator generator = key switch
        {
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pss),
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            _ => throw new NotSupportedException($"Unsupported key type '{key.GetType().Name}'.")
        };

        var serialNumber = new byte[8];
        RandomNumberGenerator.Fill(serialNumber);

        // issuerName == subjectName for self-signed; generator provides the TPM signature.
        return request.Create(dn, generator, notBefore, notAfter, serialNumber);
    }

    /// <summary>
    /// Returns a single-entry published chain (NewWithNew only) for a freshly created profile.
    /// <para>
    /// During key rollover use <see cref="CaProfile.RollOver"/> which automatically produces
    /// the full OldWithOld / OldWithNew / NewWithOld bundle.
    /// </para>
    /// </summary>
    private static X509Certificate2Collection CreateInitialPublishedChain(X509Certificate2 cert)
        => [X509Certificate2.CreateFromPem(cert.ExportCertificatePem())];
}

