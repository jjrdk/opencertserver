using System.Security.Cryptography.X509Certificates;
using CertesSlim.Pkcs;

namespace CertesSlim.Acme;

/// <summary>
/// Represents the certificate chain downloaded from ACME server.
/// </summary>
public class CertificateChain
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateChain"/> class.
    /// </summary>
    /// <param name="certificateChain">The certificate chain.</param>
    public CertificateChain(string certificateChain)
    {
        var certificates = certificateChain
            .Split(new[] { "-----END CERTIFICATE-----" }, StringSplitOptions.RemoveEmptyEntries)
            .Where(c => !string.IsNullOrWhiteSpace(c))
            .Select(c => c + "-----END CERTIFICATE-----")
            .ToArray();

        Certificate = X509Certificate2.CreateFromPem(certificates[0]);
        Issuers = new X509Certificate2Collection(certificates.Skip(1).Select(c => X509Certificate2.CreateFromPem(c))
            .ToArray());
    }

    /// <summary>
    /// Gets or sets the certificate.
    /// </summary>
    /// <value>
    /// The certificate.
    /// </value>
    public X509Certificate2 Certificate { get; }

    /// <summary>
    /// Gets or sets the issuers.
    /// </summary>
    /// <value>
    /// The issuers.
    /// </value>
    public X509Certificate2Collection Issuers { get; }

    /// <summary>
    /// Checks if the certificate chain is signed by a preferred issuer.
    /// </summary>
    /// <param name="preferredChain">The name of the preferred issuer</param>
    /// <returns>true if a certificate in the chain is issued by preferredChain or preferredChain is empty</returns>
    public bool MatchesPreferredChain(string? preferredChain)
    {
        if (string.IsNullOrEmpty(preferredChain))
        {
            return true;
        }

        X509Certificate2[] allcerts = [Certificate, ..Issuers];
        return allcerts
            .Any(cert => cert.IssuerName.Name.Contains(preferredChain));
    }

    /// <summary>
    /// Exports the certificate chain to PEM format.
    /// </summary>
    /// <returns></returns>
    public string ToPem(IKey? certKey = null)
    {
        if (certKey != null)
        {
            return $"{certKey.ToPem().TrimEnd()}\n{ToPem()}";
        }

        var certStore = new CertificateStore();
        foreach (var issuer in Issuers)
        {
            certStore.Add(issuer);
        }

        var issuers = certStore.GetIssuers(Certificate);

        X509Certificate2[] allcerts = [Certificate, ..issuers];
        return string.Join("\n", allcerts.Select(c => c.ExportCertificatePem()));
    }
}
