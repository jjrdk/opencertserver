namespace OpenCertServer.Acme.Yarp.Tests;

using System.Threading.Tasks;
using Acme.AspNetClient.Certes;

/// <summary>
/// An <see cref="IAcmeClientFactory"/> that hands out a caller-supplied <see cref="IAcmeClient"/>,
/// used to inject a fake ACME client (rather than the real, network-bound one) into the renewal
/// engine.
/// </summary>
internal sealed class TestAcmeClientFactory : IAcmeClientFactory
{
    private readonly IAcmeClient _client;

    public TestAcmeClientFactory(IAcmeClient client)
    {
        _client = client;
    }

    public Task<IAcmeClient> GetClient()
        => Task.FromResult(_client);
}
