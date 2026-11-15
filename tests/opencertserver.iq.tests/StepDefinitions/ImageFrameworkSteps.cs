namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Reflection;
using System.Runtime.Versioning;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

[Binding]
[Scope(Feature = "IQ images target the test assembly framework")]
public sealed class ImageFrameworkSteps
{
    [Then("the IQ image target matches the compiled test assembly framework")]
    public void TargetMatchesTestAssembly()
    {
#if NET10_0
        const string expected = "net10.0";
#elif NET11_0
        const string expected = "net11.0";
#else
#error Add the expected IQ test framework.
#endif
        var framework = typeof(IqImages).Assembly.GetCustomAttribute<TargetFrameworkAttribute>();
        Assert.NotNull(framework);
        Assert.Equal($".NETCoreApp,Version=v{expected["net".Length..]}", framework.FrameworkName);
        Assert.Equal(expected, IqImages.TargetFramework);
    }

    [Then("the IQ {string} image tag includes the compiled framework and the test run identity")]
    public void ImageTagIsIsolated(string image)
    {
        Assert.Equal(
            $"opencertserver-iq-{image}:{IqImages.TargetFramework}-{RepositoryPaths.RunId}",
            IqImages.ImageName(image));
        Assert.True(Guid.TryParseExact(RepositoryPaths.RunId, "N", out _));
        Assert.DoesNotContain("ContainerTestRunHooks",
            typeof(IqImages).Assembly.GetTypes().Select(type => type.Name));
    }

    [Then("the IQ publish artifacts are isolated to the test run")]
    public void PublishArtifactsAreIsolated()
    {
        Assert.Equal(Path.Combine(RepositoryPaths.Root, "artifacts", "iq", RepositoryPaths.RunId),
            RepositoryPaths.IqArtifacts);
    }
}
