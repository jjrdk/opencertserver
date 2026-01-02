using Cake.Common.Tools.DotNet;
using Cake.Common.Tools.DotNet.Publish;
using Cake.Docker;
using Cake.Frosting;

namespace OpenCertServer.Build;

[TaskName("Linux-Docker-Build")]
[IsDependentOn(typeof(PackTask))]
public sealed class LinuxDockerBuildTask : FrostingTask<BuildContext>
{
    /// <inheritdoc />
    public override void Run(BuildContext context)
    {
        var publishSettings = new DotNetPublishSettings
        {
            PublishTrimmed = true,
            Runtime = "linux-musl-x64",
            SelfContained = true,
            Framework = "net10.0",
            Configuration = context.BuildConfiguration,
            OutputDirectory = "./artifacts/publish/linux-musl-x64/"
        };

        context.DotNetPublish("./src/opencertserver.certserver/opencertserver.certserver.csproj", publishSettings);
        var settings = new DockerImageBuildSettings
        {
            NoCache = true,
            Pull = true,
            Compress = true,
            File = "./Dockerfile",
            ForceRm = true,
            Rm = true,
            Tag = ["jjrdk/opencertserver:latest", $"jjrdk/opencertserver:{context.BuildVersion}"]
        };
        context.DockerBuild(settings, "./");
    }
}
