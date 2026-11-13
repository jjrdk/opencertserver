namespace OpenCertServer.Ca.Server;

using System.Security.Cryptography.X509Certificates;

internal class ValidateAll : IValidateX509Chains
{
    public Task<bool> Validate(X509Chain chain, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(true);
    }
}