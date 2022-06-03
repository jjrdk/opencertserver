namespace opencertserver.certserver;

using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Model;

internal class DefaultCsrValidator : ICsrValidator
{
    /// <inheritdoc />
    public Task<(bool isValid, AcmeError? error)> ValidateCsr(Order order, string csr, CancellationToken cancellationToken)
    {
        return Task.FromResult((true, (AcmeError?)null));
    }
}