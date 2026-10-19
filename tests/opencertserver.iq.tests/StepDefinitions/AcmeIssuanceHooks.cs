namespace OpenCertServer.Iq.Tests.StepDefinitions;

using OpenCertServer.Iq.Tests.Support;
using Reqnroll;

/// <summary>
/// Starts one <see cref="IqAcmeEnvironment"/> (network, DNS, server, client) per feature run and tears it down
/// afterwards; on a failed scenario the container logs are written to the test output.
/// </summary>
[Binding]
[Scope(Feature = AcmeIssuanceSteps.FeatureTitle)]
[Scope(Feature = AuthorityInformationSteps.FeatureTitle)]
[Scope(Feature = CrlRevocationSteps.FeatureTitle)]
[Scope(Feature = OcspResponderSteps.FeatureTitle)]
[Scope(Feature = EstEnrollmentSteps.FeatureTitle)]
[Scope(Feature = LinuxServerDeploymentSteps.FeatureTitle)]
[Scope(Feature = OpenCertCliSteps.FeatureTitle)]
[Scope(Feature = OpenTelemetrySteps.FeatureTitle)]
[Scope(Feature = ProfileIssuanceSteps.FeatureTitle)]
[Scope(Feature = DeviceAttestationSteps.FeatureTitle)]
[Scope(Feature = PenetrationSteps.FeatureTitle)]
public sealed class AcmeIssuanceHooks
{
    private readonly FeatureContext _featureContext;
    private readonly ScenarioContext _scenarioContext;
    private readonly IReqnrollOutputHelper _output;
    private readonly AcmeScenarioState _state;

    public AcmeIssuanceHooks(
        FeatureContext featureContext,
        ScenarioContext scenarioContext,
        IReqnrollOutputHelper output,
        AcmeScenarioState state)
    {
        _featureContext = featureContext;
        _scenarioContext = scenarioContext;
        _output = output;
        _state = state;
    }

    [BeforeFeature]
    public static async Task StartEnvironment(FeatureContext featureContext)
    {
        IqAuthorityConfiguration? authorityConfiguration = null;
        IqRevocationConfiguration? revocationConfiguration = null;
        var isEst = featureContext.FeatureInfo.Title == EstEnrollmentSteps.FeatureTitle;
        var isOcsp = featureContext.FeatureInfo.Title == OcspResponderSteps.FeatureTitle;
        var isCli = featureContext.FeatureInfo.Title == OpenCertCliSteps.FeatureTitle;
        var isTelemetry = featureContext.FeatureInfo.Title == OpenTelemetrySteps.FeatureTitle;
        var isProfile = featureContext.FeatureInfo.Title == ProfileIssuanceSteps.FeatureTitle;
        if (featureContext.FeatureInfo.Title == CrlRevocationSteps.FeatureTitle || isEst || isOcsp || isCli || isTelemetry)
        {
            revocationConfiguration = new IqRevocationConfiguration();
            featureContext.Set(revocationConfiguration);
        }

        if (featureContext.FeatureInfo.Title is AuthorityInformationSteps.FeatureTitle or CrlRevocationSteps.FeatureTitle
            || isEst || isOcsp || isCli || isTelemetry || isProfile)
        {
            authorityConfiguration = new IqAuthorityConfiguration(
                revocationConfiguration is null ? "https://iq.test" : IqRevocationConfiguration.IssuerUrl,
                publishCsrTemplate: isEst, qualifyProfileIssuance: isProfile);
            featureContext.Set(authorityConfiguration);
        }

        var environment = await IqAcmeEnvironment.StartAsync(
                authorityConfiguration: authorityConfiguration, revocationConfiguration: revocationConfiguration,
                enableHttp: featureContext.FeatureInfo.Title is LinuxServerDeploymentSteps.FeatureTitle
                    or PenetrationSteps.FeatureTitle,
                enableTelemetry: isTelemetry)
            .ConfigureAwait(false);
        featureContext.Set(environment);
        if (environment.TelemetryCollector is { } collector)
        {
            featureContext.Set(collector, "TelemetryCollector");
        }
    }

    [AfterFeature]
    public static async Task StopEnvironment(FeatureContext featureContext)
    {
        if (featureContext.TryGetValue(out IqAcmeEnvironment environment))
        {
            await environment.DisposeAsync().ConfigureAwait(false);
        }
    }

    [BeforeScenario(Order = 0)]
    public void ShareEnvironment()
    {
        _scenarioContext.Set(_featureContext.Get<IqAcmeEnvironment>());
        if (_featureContext.TryGetValue(out IqRevocationConfiguration configuration))
        {
            _scenarioContext.Set(configuration.AdminToken, "CrlAdminToken");
            _scenarioContext.Set(configuration.UserToken, "CrlUserToken");
            _scenarioContext.Set(configuration.EnrollmentToken, "EstToken");
        }
    }

    [AfterScenario]
    public async Task CollectDiagnostics()
    {
        var state = _state;
        try
        {
            if (_scenarioContext.TestError != null)
            {
                var environment = _featureContext.Get<IqAcmeEnvironment>();
                if (state.LastExec is { } exec)
                {
                    _output.WriteLine($"Last client command exited {exec.ExitCode}:\n{exec.Stdout}\n{exec.Stderr}");
                }

                _output.WriteLine(await environment.GetDiagnosticsAsync(state.TosServer).ConfigureAwait(false));
            }
        }
        finally
        {
            if (state.TosServer != null)
            {
                await state.TosServer.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}
