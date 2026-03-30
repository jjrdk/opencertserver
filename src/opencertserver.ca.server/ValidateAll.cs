using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Server;

internal class ValidateAll : IValidateX509Chains
{
    public Task<bool> Validate(X509Chain chain, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(true);
    }
}
