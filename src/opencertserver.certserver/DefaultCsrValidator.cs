namespace OpenCertServer.CertServer;

using Acme.Abstractions.IssuanceServices;
using Acme.Abstractions.Model;

internal sealed class DefaultCsrValidator : ICsrValidator
{
    /// <inheritdoc />
    public Task<(bool isValid, AcmeError? error)> ValidateCsr(Order order, string csr, CancellationToken cancellationToken)
    {
        return Task.FromResult((true, (AcmeError?)null));
    }
}
