namespace OpenCertServer.CertServer;

using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Model;

internal sealed class DefaultCsrValidator : ICsrValidator
{
    /// <inheritdoc />
    public Task<(bool isValid, AcmeError? error)> ValidateCsr(Order order, string csr, CancellationToken cancellationToken)
    {
        return Task.FromResult((true, (AcmeError?)null));
    }
}