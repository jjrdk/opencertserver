namespace OpenCertServer.Build;

using Cake.Common.Tools.DotNet;
using Cake.Common.Tools.DotNet.Publish;
using Cake.Core.Diagnostics;
using Cake.Frosting;

[TaskName("CLI Publish")]
[IsDependentOn(typeof(LinuxDockerBuildTask))]
public sealed class CliPublishTask : FrostingTask<BuildContext>
{
    /// <inheritdoc />
    public override void Run(BuildContext context)
    {
        var runtimes = new[]
        {
            "linux-musl-x64", "linux-x64", "linux-arm64", "linux-arm64", "osx-arm64", "win-x64", "win-x86", "win-arm64"
        };
        foreach (var runtime in runtimes)
        {
            context.Log.Information($"Publishing CLI for runtime: {runtime}");
            var publishSettings = new DotNetPublishSettings
            {
                PublishTrimmed = true,
                Runtime = runtime,
                SelfContained = true,
                Framework = "net10.0",
                Configuration = context.BuildConfiguration,
                OutputDirectory = $"./artifacts/publish/cli/{runtime}/",
                EnableCompressionInSingleFile = true,
                IncludeAllContentForSelfExtract = true,
                IncludeNativeLibrariesForSelfExtract = true,
                NoLogo = true,
                PublishReadyToRun = true,
                PublishSingleFile = true,
                RollForward = DotNetRollForward.LatestPatch
            };

            context.DotNetPublish("./src/opencertserver.cli/opencertserver.cli.csproj", publishSettings);
        }
    }
}
