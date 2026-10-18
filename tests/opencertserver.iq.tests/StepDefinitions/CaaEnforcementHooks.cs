namespace OpenCertServer.Iq.Tests.StepDefinitions;

using OpenCertServer.Iq.Tests.Support;
using Reqnroll;

/// <summary>Isolates CAA configuration and DNS records in a disposable topology per scenario.</summary>
[Binding]
[Scope(Feature = AcmeIssuanceSteps.CaaFeatureTitle)]
public sealed class CaaEnforcementHooks
{
    [BeforeScenario(Order = 0)]
    public static async Task StartEnvironment(ScenarioContext scenarioContext)
    {
        var environment = await IqAcmeEnvironment.StartAsync(
                disableCaaChecks: scenarioContext.ScenarioInfo.Tags.Contains("caa-disabled"))
            .ConfigureAwait(false);
        scenarioContext.Set(environment);
    }

    [AfterScenario]
    public static async Task StopEnvironment(
        ScenarioContext scenarioContext, AcmeScenarioState state, IReqnrollOutputHelper output)
    {
        if (!scenarioContext.TryGetValue(out IqAcmeEnvironment environment))
        {
            return;
        }

        try
        {
            if (scenarioContext.TestError != null)
            {
                if (state.LastExec is { } exec)
                {
                    output.WriteLine($"Last client command exited {exec.ExitCode}:\n{exec.Stdout}\n{exec.Stderr}");
                }

                output.WriteLine(await environment.GetDiagnosticsAsync().ConfigureAwait(false));
            }
        }
        finally
        {
            await environment.DisposeAsync().ConfigureAwait(false);
        }
    }
}
