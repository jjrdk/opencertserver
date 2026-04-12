namespace OpenCertServer.Tpm.Tests;

using System.Threading.Tasks;
using Reqnroll;

/// <summary>
/// Reqnroll hooks that spin up a single IBM TPM2 simulator container for the entire
/// feature and share it across all scenarios.  Persistent TPM handles are idempotent
/// (<c>EnsureRsaKey</c>/<c>EnsureEcDsaKey</c> are no-ops if the key already exists),
/// so scenarios do not interfere with each other even when they use the same handles.
/// Using one container instead of one-per-scenario cuts total container lifecycle overhead
/// from O(n) to O(1) and keeps the feature runtime well under five minutes.
/// </summary>
[Binding]
public sealed class TpmContainerHooks
{
    private readonly ScenarioContext _scenarioContext;
    private readonly FeatureContext _featureContext;

    public TpmContainerHooks(ScenarioContext scenarioContext, FeatureContext featureContext)
    {
        _scenarioContext = scenarioContext;
        _featureContext = featureContext;
    }

    /// <summary>
    /// Starts one simulator container for the whole feature.  Subsequent calls within the
    /// same feature reuse the existing container via <see cref="FeatureContext"/>.
    /// </summary>
    [BeforeFeature(Order = 0)]
    public static async Task StartTpmSimulatorForFeatureAsync(FeatureContext featureContext)
    {
        var container = await TpmSimulatorContainer.CreateAsync();
        featureContext.Set(container);
    }

    /// <summary>
    /// Makes the shared container available via <see cref="ScenarioContext"/> so that
    /// step definitions can retrieve it with <c>scenarioContext.Get&lt;TpmSimulatorContainer&gt;()</c>.
    /// </summary>
    [BeforeScenario(Order = 0)]
    public void InjectContainerIntoScenario()
    {
        var container = _featureContext.Get<TpmSimulatorContainer>();
        _scenarioContext.Set(container);
    }

    /// <summary>Disposes the shared container after the last scenario in the feature.</summary>
    [AfterFeature]
    public static async Task StopTpmSimulatorForFeatureAsync(FeatureContext featureContext)
    {
        if (featureContext.TryGetValue<TpmSimulatorContainer>(out var container))
        {
            await container.DisposeAsync();
        }
    }
}

