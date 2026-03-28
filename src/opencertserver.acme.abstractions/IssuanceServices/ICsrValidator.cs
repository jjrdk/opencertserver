namespace OpenCertServer.Acme.Abstractions.IssuanceServices;

using System.Threading;
using System.Threading.Tasks;
using Model;

/// <summary>
/// Defines a service for validating certificate signing requests (CSRs) for ACME orders.
/// </summary>
public interface ICsrValidator
{
    /// <summary>
    /// Validates the provided CSR for the given order.
    /// </summary>
    /// <param name="order">The ACME order to validate against.</param>
    /// <param name="csr">The PEM or DER-encoded certificate signing request.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A tuple indicating whether the CSR is valid and an optional error.</returns>
    Task<(bool isValid, AcmeError? error)> ValidateCsr(Order order, string csr, CancellationToken cancellationToken);
}
