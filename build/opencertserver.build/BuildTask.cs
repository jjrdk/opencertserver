namespace OpenCertServer.Build;

using Cake.Common.Tools.DotNet;
using Cake.Common.Tools.DotNet.MSBuild;
using Cake.Frosting;

[TaskName("Build")]
[IsDependentOn(typeof(RestoreNugetPackagesTask))]
public sealed class BuildTask : FrostingTask<BuildContext>
{
    /// <inheritdoc />
    public override void Run(BuildContext context)
    {
        var buildSettings = new DotNetMSBuildSettings().SetConfiguration(context.BuildConfiguration)
            .SetVersion(context.BuildVersion)
            .SetInformationalVersion(context.InformationalVersion);
        context.DotNetMSBuild(context.SolutionName, buildSettings);
    }
}
