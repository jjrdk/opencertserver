namespace OpenCertServer.Contrib.Intune.Tests.Steps;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Reqnroll;
using Xunit;

[Binding]
public sealed class IntuneDeviceName : IDisposable
{
    private readonly FakeIntune _fake = new();
    private IHost? _host;
    private string? _name;
    private Exception? _error;

    [Given("the Intune device {string} is called {string}")]
    public void GivenDeviceName(string id, string name)
    {
        _fake.ManagedDevices[id] = 0;
        _fake.DeviceNames[id] = name;
    }

    [Given("Graph answers with HTTP 429 for device names")]
    public void GivenThrottled() => _fake.Graph = GraphBehaviour.Throttle;

    [When("the name of the Intune device {string} is asked")]
    public async Task WhenAsked(string id)
    {
        _host ??= TestHostBuilder.Build(_fake).Host;
        var client = _host.Services.GetRequiredService<IIntuneClient>();
        try
        {
            _name = await client.GetManagedDeviceName(id, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _error = ex;
        }
    }

    [Then("the name is {string}")]
    public void ThenName(string name)
    {
        Assert.Null(_error);
        Assert.Equal(name, _name);
    }

    [Then("there is no name")]
    public void ThenNoName()
    {
        Assert.Null(_error);
        Assert.Null(_name);
    }

    [Then("the lookup reports Graph as unavailable")]
    public void ThenUnavailable() => Assert.IsType<GraphUnavailableException>(_error);

    public void Dispose() => _host?.Dispose();
}
