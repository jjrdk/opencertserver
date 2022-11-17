namespace OpenCertServer.Build;

using Cake.Common.Tools.DotNet;
using Cake.Common.Tools.DotNet.MSBuild;
using Cake.Common.Tools.DotNet.Pack;
using Cake.Common.Tools.DotNet.Publish;
using Cake.Core.Diagnostics;
using Cake.Docker;
using Cake.Frosting;

[TaskName("Pack")]
[IsDependentOn(typeof(TestsTask))]
public sealed class PackTask : FrostingTask<BuildContext>
{
    /// <inheritdoc />
    public override void Run(BuildContext context)
    {
        context.Log.Information("Package version: " + context.BuildVersion);

        var packSettings = new DotNetPackSettings
        {
            Configuration = context.BuildConfiguration,
            NoBuild = true,
            NoRestore = true,
            OutputDirectory = "./artifacts/packages",
            IncludeSymbols = true,
            MSBuildSettings = new DotNetMSBuildSettings().SetConfiguration(context.BuildConfiguration)
                .SetVersion(context.BuildVersion)
        };

        context.DotNetPack("./src/opencertserver.est.client/opencertserver.est.client.csproj", packSettings);
        context.DotNetPack("./src/opencertserver.est.server/opencertserver.est.server.csproj", packSettings);
        context.DotNetPack("./src/opencertserver.ca/opencertserver.ca.csproj", packSettings);
        context.DotNetPack("./src/opencertserver.ca.utils/opencertserver.ca.utils.csproj", packSettings);
        context.DotNetPack("./src/opencertserver.acme.abstractions/opencertserver.acme.abstractions.csproj", packSettings);
        context.DotNetPack("./src/opencertserver.acme.server/opencertserver.acme.server.csproj", packSettings);
        context.DotNetPack("./src/opencertserver.acme.aspnetclient/opencertserver.acme.aspnetclient.csproj", packSettings);
    }
}


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
            Tag = new[]
            {
                "jjrdk/opencertserver:latest", $"jjrdk/opencertserver:{context.BuildVersion}"
            }
        };
        context.DockerBuild(settings, "./");
    }
}