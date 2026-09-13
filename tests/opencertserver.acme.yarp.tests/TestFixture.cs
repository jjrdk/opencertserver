namespace OpenCertServer.Acme.Yarp.Tests;

using System;
using System.Threading;
using System.Threading.Tasks;
using Acme.AspNetClient.Certes;
using Microsoft.Extensions.Hosting;

/// <summary>
/// A no-op <see cref="IHostApplicationLifetime"/> so the <see cref="AcmeRenewalService"/> can be
/// constructed and driven directly in a unit test without a running host.
/// </summary>
internal sealed class FakeHostApplicationLifetime : IHostApplicationLifetime
{
    public CancellationToken ApplicationStarted { get; } = CancellationToken.None;

    public CancellationToken ApplicationStopping { get; } = CancellationToken.None;

    public CancellationToken ApplicationStopped { get; } = CancellationToken.None;

    public CancellationToken RegisterStarted(Action applicationStarted)
        => CancellationToken.None;

    public CancellationToken RegisterStopping(Action applicationStopping)
        => CancellationToken.None;

    public CancellationToken RegisterStopped(Action applicationStopped)
        => CancellationToken.None;

    public void StartApplication()
    {
    }

    public void StopApplication()
    {
    }
}

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
