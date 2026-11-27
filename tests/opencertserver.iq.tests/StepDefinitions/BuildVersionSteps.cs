namespace OpenCertServer.Iq.Tests.StepDefinitions;

using OpenCertServer.Build;
using Reqnroll;
using Xunit;

[Binding]
[Scope(Feature = "Cake build version formatting")]
public sealed class BuildVersionSteps
{
    private string? _buildVersion;

    [When("the build version is formatted for branch {string}, version {string}, and distance {int}")]
    public void WhenTheBuildVersionIsFormatted(string branch, string version, int distance)
    {
        _buildVersion = VersionTask.FormatBuildVersion(branch, version, distance);
    }

    [Then("the build version is {string}")]
    public void ThenTheBuildVersionIs(string expected)
    {
        Assert.Equal(expected, _buildVersion);
    }
}
