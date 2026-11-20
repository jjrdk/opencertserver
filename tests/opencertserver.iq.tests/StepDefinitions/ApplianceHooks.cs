namespace OpenCertServer.Iq.Tests.StepDefinitions;

using OpenCertServer.Iq.Tests.Support;
using Reqnroll;

/// <summary>
/// The chiseled appliance IQ scenarios boot one appliance container per role, so the environment is
/// created and torn down per scenario (unlike the ACME features, which share one environment across a
/// feature). The <c>Given</c> that names the role starts it; this hook disposes it and, on a failed
/// scenario, writes the appliance logs to the test output.
/// </summary>
[Binding]
[Scope(Feature = ApplianceContainerSteps.FeatureTitle)]
public sealed class ApplianceHooks
{
    private readonly ScenarioContext _scenarioContext;
    private readonly IReqnrollOutputHelper _output;

    public ApplianceHooks(ScenarioContext scenarioContext, IReqnrollOutputHelper output)
    {
        _scenarioContext = scenarioContext;
        _output = output;
    }

    [AfterScenario]
    public async Task DisposeEnvironment()
    {
        if (!_scenarioContext.TryGetValue(out IqApplianceEnvironment environment))
        {
            return;
        }

        try
        {
            if (_scenarioContext.TestError != null)
            {
                _output.WriteLine(await environment.ServerLogsAsync().ConfigureAwait(false));
            }
        }
        finally
        {
            await environment.DisposeAsync().ConfigureAwait(false);
        }
    }
}
