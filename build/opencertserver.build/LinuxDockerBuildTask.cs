namespace OpenCertServer.Build;

using Cake.Common.Tools.DotNet;
using Cake.Common.Tools.DotNet.Publish;
using Cake.Docker;
using Cake.Frosting;

[TaskName("Linux-Docker-Build")]
[IsDependentOn(typeof(PackTask))]
public sealed class LinuxDockerBuildTask : FrostingTask<BuildContext>
{
    /// <inheritdoc />
    public override void Run(BuildContext context)
    {
        foreach (var framework in ApplianceDockerBuildTask.Frameworks)
        {
            var publishSettings = new DotNetPublishSettings
            {
                PublishTrimmed = false,
                Runtime = "linux-musl-x64",
                SelfContained = true,
                Framework = framework.TargetFramework,
                Configuration = context.BuildConfiguration,
                OutputDirectory = $"./artifacts/publish/{framework.TargetFramework}/server/linux-musl-x64/"
            };
            context.DotNetPublish("./src/opencertserver.certserver/opencertserver.certserver.csproj", publishSettings);

            var tags = framework.TargetFramework == "net10.0"
                ? new[]
                {
                    "jjrdk/opencertserver:latest",
                    $"jjrdk/opencertserver:{context.BuildVersion}",
                    $"jjrdk/opencertserver:latest-{framework.TargetFramework}",
                    $"jjrdk/opencertserver:{context.BuildVersion}-{framework.TargetFramework}"
                }
                : new[]
                {
                    $"jjrdk/opencertserver:latest-{framework.TargetFramework}",
                    $"jjrdk/opencertserver:{context.BuildVersion}-{framework.TargetFramework}"
                };
            var settings = new DockerImageBuildSettings
            {
                NoCache = true,
                Pull = true,
                Compress = true,
                File = "./Dockerfile",
                ForceRm = true,
                Rm = true,
                BuildArg = [$"TFM={framework.TargetFramework}", $"DOTNET_VERSION={framework.RuntimeVersion}"],
                Tag = tags
            };
            context.DockerBuild(settings, "./");
        }
    }
}
