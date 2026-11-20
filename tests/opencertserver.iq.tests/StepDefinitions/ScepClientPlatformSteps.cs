namespace OpenCertServer.Iq.Tests.StepDefinitions;

using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

[Binding]
[Scope(Feature = "SCEP clients target Docker independently of the test host")]
public sealed class ScepClientPlatformSteps
{
    private string _operatingSystem = "";
    private string _architecture = "";
    private string _override = "";
    private IqDockerPlatform? _platform;
    private Exception? _error;

    [Given("Docker reports operating system {string} and architecture {string}")]
    public void DockerEnvironment(string operatingSystem, string architecture)
    {
        _operatingSystem = operatingSystem;
        _architecture = architecture;
    }

    [Given("the IQ Docker architecture override is {string}")]
    public void ArchitectureOverride(string architecture) => _override = architecture;

    [When("the IQ client platform is selected")]
    public void SelectPlatform() =>
        _error = Record.Exception(() => _platform = IqDockerPlatform.Resolve(_operatingSystem, _architecture, _override));

    [Then("the IQ binaries target architecture {string} and the client image targets {string}")]
    public void AssertPlatform(string architecture, string platform)
    {
        Assert.Null(_error);
        Assert.NotNull(_platform);
        Assert.Equal(architecture, _platform.Architecture);
        Assert.Equal(platform, _platform.Platform);
    }

    [Then("client platform selection fails with {string}")]
    public void AssertFailure(string error)
    {
        var exception = Assert.IsType<InvalidOperationException>(_error);
        Assert.Contains(error, exception.Message, StringComparison.Ordinal);
        Assert.Null(_platform);
    }
}
