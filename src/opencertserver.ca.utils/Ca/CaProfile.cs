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

    /// <summary>
    /// Gets or sets the name of the CA profile.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Gets the private key associated with the CA profile.
    /// </summary>
    public required AsymmetricAlgorithm PrivateKey { get; init; }

    /// <summary>
    /// Gets the certificate chain associated with the CA profile.
    /// </summary>
    public required X509Certificate2Collection CertificateChain { get; init; }

    /// <summary>
    /// Gets the certificates that should be published to EST clients.
    /// When empty, <see cref="CertificateChain"/> is published.
    /// </summary>
    public X509Certificate2Collection PublishedCertificateChain { get; init; } = [];

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
        _crlNumber += BigInteger.One;
        return CrlNumber;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        PrivateKey.Dispose();
        foreach (var cert in CertificateChain)
        {
            cert.Dispose();
        }

        foreach (var cert in PublishedCertificateChain)
        {
            if (CertificateChain.Any(existing => ReferenceEquals(existing, cert)))
            {
                continue;
            }

            cert.Dispose();
        }

        GC.SuppressFinalize(this);
    }
}
