namespace OpenCertServer.Acme.Abstractions.IssuanceServices;

using System;
using System.Threading;
using System.Threading.Tasks;
using Model;

/// <summary>
/// Defines a service for issuing certificates for ACME orders.
/// </summary>
public interface IIssueCertificates
{
    /// <summary>
    /// Issues a certificate for the given identifiers and CSR, using the specified profile.
    /// </summary>
    /// <param name="profile">The certificate profile to use, or null for default.</param>
    /// <param name="csr">The PEM or DER-encoded certificate signing request.</param>
    /// <param name="identifiers">The identifiers to include in the certificate.</param>
    /// <param name="notBefore">The requested not-before date/time, if accepted for the order.</param>
    /// <param name="notAfter">The requested not-after date/time, if accepted for the order.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A tuple containing the issued certificate (as bytes) and an optional error.</returns>
    Task<(byte[]? certificate, AcmeError? error)> IssueCertificate(
        string? profile,
        string csr,
        IEnumerable<Identifier> identifiers,
        DateTimeOffset? notBefore,
        DateTimeOffset? notAfter,
        CancellationToken cancellationToken);
}
