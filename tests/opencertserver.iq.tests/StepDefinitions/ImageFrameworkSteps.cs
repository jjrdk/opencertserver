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
}
