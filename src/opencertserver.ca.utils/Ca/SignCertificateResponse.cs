namespace OpenCertServer.Ca.Utils.Ca;

using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Represents the result of a certificate signing operation.
/// </summary>
public abstract class SignCertificateResponse
{
    /// <summary>
    /// Represents a successful certificate signing result.
    /// </summary>
    public sealed class Success : SignCertificateResponse
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Success"/> class.
        /// </summary>
        public Success(X509Certificate2 certificate, X509Certificate2Collection issuers)
        {
            Certificate = certificate;
            Issuers = issuers;
        }

        /// <summary>
        /// Gets the issued certificate.
        /// </summary>
        public X509Certificate2 Certificate { get; }

        /// <summary>
        /// Gets the issuer certificate chain.
        /// </summary>
        public X509Certificate2Collection Issuers { get; }
    }

    /// <summary>
    /// Represents a failed certificate signing result.
    /// </summary>
    public sealed class Error : SignCertificateResponse
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Error"/> class.
        /// </summary>
        public Error(params Span<string> errors)
        {
            Errors = [..errors];
        }

        /// <summary>
        /// Gets the list of signing errors.
        /// </summary>
        public ImmutableArray<string> Errors { get; }
    }
}
