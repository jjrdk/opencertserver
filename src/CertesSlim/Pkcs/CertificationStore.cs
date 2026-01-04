using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using CertesSlim.Properties;

namespace CertesSlim.Pkcs
{
    /// <summary>
    /// Represents a collection of X509 certificates.
    /// </summary>
    public class CertificateStore
    {
        private readonly Dictionary<string, X509Certificate2> _certificates = new();

        private readonly Lazy<Dictionary<string, X509Certificate2>> _embeddedCertificates = new(() =>
        {
            var assembly = typeof(CertificateStore).GetTypeInfo().Assembly;
            return assembly
                .GetManifestResourceNames()
                .Where(n => n.EndsWith(".pem"))
                .Select(n =>
                {
                    using var stream = assembly.GetManifestResourceStream(n);
                    Span<byte> pemData = stackalloc byte[(int)stream!.Length];
                    stream.ReadExactly(pemData);
                    return X509CertificateLoader.LoadCertificate(pemData);
                })
                .ToDictionary(c => c.SubjectName.Format(false), c => c);
        }, true);

        /// <summary>
        /// Adds issuer certificates.
        /// </summary>
        /// <param name="certificate">The issuer certificate.</param>
        public void Add(X509Certificate2 certificate)
        {
            _certificates[certificate.SubjectName.Format(false)] = certificate;
        }

        /// <summary>
        /// Gets the issuers of given certificate.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <returns>
        /// The issuers of the certificate.
        /// </returns>
        public X509Certificate2Collection GetIssuers(X509Certificate2 certificate)
        {
            var chain = new X509Certificate2Collection();
            while (!certificate.SubjectName.Format(false)
                .Equals(certificate.IssuerName.Format(false), StringComparison.OrdinalIgnoreCase))
            {
                if (_certificates.TryGetValue(certificate.IssuerName.Format(false), out var issuer) ||
                    _embeddedCertificates.Value.TryGetValue(certificate.IssuerName.Format(false), out issuer))
                {
                    chain.Add(issuer);
                    certificate = issuer;
                }
                else
                {
                    throw new AcmeException(
                        string.Format(Strings.ErrorIssuerNotFound, certificate.IssuerName, certificate.SubjectName));
                }
            }

            return chain;
        }
    }
}
