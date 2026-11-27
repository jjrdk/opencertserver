namespace OpenCertServer.Iq.Tests.StepDefinitions;

using OpenCertServer.Build;
using Reqnroll;
using Xunit;

[Binding]
[Scope(Feature = "Appliance Docker build configuration")]
public sealed class ApplianceDockerBuildSteps
{
    private ApplianceDockerBuildTask.FrameworkSpec _framework = null!;

    [Given("the appliance build targets {string}")]
    public void GivenTheFramework(string framework)
    {
        Assert.Equal(["net10.0", "net11.0"],
            ApplianceDockerBuildTask.Frameworks.Select(item => item.TargetFramework));
        _framework = Assert.Single(ApplianceDockerBuildTask.Frameworks, item => item.TargetFramework == framework);
    }

    [Then("each appliance role is published for that framework with its matching globalization setting")]
    public void ThenEachRoleIsPublished()
    {
        Assert.Equal(["ca", "ra", "unified"], ApplianceDockerBuildTask.Roles.Select(role => role.Name));
        foreach (var role in ApplianceDockerBuildTask.Roles)
        {
            foreach (var mssql in new[] { false, true })
            {
                var settings = ApplianceDockerBuildTask.PublishSettings(role, _framework, "Release", mssql);
                Assert.Equal(_framework.TargetFramework, settings.Framework);
                Assert.Equal("linux-x64", settings.Runtime);
                Assert.True(settings.SelfContained);
                Assert.Equal($"artifacts/publish/{_framework.TargetFramework}/{role.Name}/{(mssql ? "mssql/" : "")}linux-x64",
                    settings.OutputDirectory?.FullPath);
                Assert.Equal(mssql ? "false" : "true", Assert.Single(settings.MSBuildSettings!.Properties["InvariantGlobalization"]));
            }
        }
    }

    [Then("each appliance image uses matching build arguments and framework-qualified tags")]
    public void ThenEachImageUsesMatchingArguments()
    {
        var (version, ubuntu) = _framework.TargetFramework switch
        {
            "net10.0" => ("10.0", "noble"),
            "net11.0" => ("11.0", "resolute"),
            _ => throw new InvalidOperationException()
        };
        var files = ApplianceDockerBuildTask.Roles
            .SelectMany(role => role.BaseDockerfiles.Concat(role.MssqlDockerfiles)).ToArray();
        Assert.Equal(new[]
        {
            "./Dockerfile.ca", "./Dockerfile.ca.postgres", "./Dockerfile.ca.mssql",
            "./Dockerfile.ra", "./Dockerfile.ra.postgres", "./Dockerfile.ra.mssql",
            "./Dockerfile.unified", "./Dockerfile.appliance", "./Dockerfile.unified.postgres",
            "./Dockerfile.unified.mssql"
        }, files);
        foreach (var file in files)
        {
            var settings = ApplianceDockerBuildTask.ImageBuildSettings(file, _framework, "1.2.3");
            var suffix = Path.GetFileName(file)["Dockerfile.".Length..].Replace('.', '-');
            Assert.Equal(file, settings.File);
            Assert.Equal([$"TFM={_framework.TargetFramework}", $"DOTNET_VERSION={version}", $"UBUNTU_CODENAME={ubuntu}"],
                settings.BuildArg);
            Assert.Equal([$"opencertserver-appliance-{suffix}:latest-{_framework.TargetFramework}",
                $"opencertserver-appliance-{suffix}:1.2.3-{_framework.TargetFramework}"], settings.Tag);
        }
    }
}
