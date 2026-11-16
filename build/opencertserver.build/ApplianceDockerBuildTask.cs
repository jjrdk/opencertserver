using System;
using System.IO;
using Cake.Common.Tools.DotNet;
using Cake.Common.Tools.DotNet.MSBuild;
using Cake.Common.Tools.DotNet.Publish;
using Cake.Docker;
using Cake.Frosting;

namespace OpenCertServer.Build;

/// <summary>
/// Publishes every per-role host for each supported framework and builds its appliance images
/// with framework-qualified tags.
///
/// Each appliance Dockerfile now COPYs the publish of its own host project, so the publish is
/// per-role (not a single shared certserver binary):
///   - ca       -> artifacts/publish/&lt;tfm&gt;/ca/&lt;rid&gt;/       + artifacts/publish/&lt;tfm&gt;/ca/mssql/&lt;rid&gt;/
///   - ra       -> artifacts/publish/&lt;tfm&gt;/ra/&lt;rid&gt;/       + artifacts/publish/&lt;tfm&gt;/ra/mssql/&lt;rid&gt;/
///   - unified  -> artifacts/publish/&lt;tfm&gt;/unified/&lt;rid&gt;/  + artifacts/publish/&lt;tfm&gt;/unified/mssql/&lt;rid&gt;/
///
/// The base + postgres variants are published InvariantGlobalization (chiseled runtime ships no
/// ICU); the mssql variant is published WITHOUT invariant globalization because the SQL Server EF
/// Core provider hard-requires ICU.
///
/// The appliance images are built here only; they are not part of the default build (which targets
/// the main server and CLI), so this task is a stand-alone target that depends on
/// <see cref="PackTask"/>.
/// </summary>
[TaskName("Appliance-Docker-Build")]
[IsDependentOn(typeof(PackTask))]
public sealed class ApplianceDockerBuildTask : FrostingTask<BuildContext>
{
    internal sealed record RoleSpec(string Name, string Project, string[] BaseDockerfiles, string[] MssqlDockerfiles);
    internal sealed record FrameworkSpec(string TargetFramework, string RuntimeVersion, string UbuntuCodename);

    internal static readonly FrameworkSpec[] Frameworks =
    [
        new("net10.0", "10.0", "noble"),
        new("net11.0", "11.0", "resolute")
    ];

    // One entry per role host. The base+postgres Dockerfiles COPY from .../&lt;role&gt;/&lt;rid&gt;/
    // (invariant); the mssql Dockerfiles COPY from .../&lt;role&gt;/mssql/&lt;rid&gt;/ (no invariant).
    internal static readonly RoleSpec[] Roles =
    [
        new("ca", "./src/hosts/opencertserver.host.ca/opencertserver.host.ca.csproj",
            ["./Dockerfile.ca", "./Dockerfile.ca.postgres"],
            ["./Dockerfile.ca.mssql"]),
        new("ra", "./src/hosts/opencertserver.host.ra/opencertserver.host.ra.csproj",
            ["./Dockerfile.ra", "./Dockerfile.ra.postgres"],
            ["./Dockerfile.ra.mssql"]),
        // Dockerfile.appliance is the unified alias (same COPY path as Dockerfile.unified).
        new("unified", "./src/hosts/opencertserver.host.unified/opencertserver.host.unified.csproj",
            ["./Dockerfile.unified", "./Dockerfile.appliance", "./Dockerfile.unified.postgres"],
            ["./Dockerfile.unified.mssql"])
    ];

    public override void Run(BuildContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        foreach (var framework in Frameworks)
        {
            foreach (var role in Roles)
            {
                // Base and postgres use the ICU-less chiseled runtime.
                context.DotNetPublish(role.Project, PublishSettings(role, framework, context.BuildConfiguration, false));

                foreach (var dockerfile in role.BaseDockerfiles)
                {
                    BuildImage(context, dockerfile, framework);
                }

                // MSSQL requires ICU and uses the full runtime-deps image.
                context.DotNetPublish(role.Project, PublishSettings(role, framework, context.BuildConfiguration, true));

                foreach (var dockerfile in role.MssqlDockerfiles)
                {
                    BuildImage(context, dockerfile, framework);
                }
            }
        }
    }

    internal static DotNetPublishSettings PublishSettings(
        RoleSpec role, FrameworkSpec framework, string configuration, bool mssql) => new()
    {
        PublishTrimmed = false,
        Runtime = "linux-x64",
        SelfContained = true,
        Framework = framework.TargetFramework,
        Configuration = configuration,
        OutputDirectory = $"./artifacts/publish/{framework.TargetFramework}/{role.Name}/{(mssql ? "mssql/" : "")}linux-x64/",
        MSBuildSettings = new DotNetMSBuildSettings().WithProperty("InvariantGlobalization", mssql ? "false" : "true")
    };

    // Builds a single appliance image with framework-qualified latest and version tags.
    //
    //   Dockerfile.unified.postgres -> opencertserver-appliance-unified-postgres
    //   Dockerfile.ca               -> opencertserver-appliance-ca
    //   Dockerfile.appliance        -> opencertserver-appliance-appliance
    private static void BuildImage(BuildContext context, string dockerfile, FrameworkSpec framework)
    {
        context.DockerBuild(ImageBuildSettings(dockerfile, framework, context.BuildVersion), "./");
    }

    internal static DockerImageBuildSettings ImageBuildSettings(string dockerfile, FrameworkSpec framework, string version)
    {
        var image = ImageName(dockerfile);
        return new DockerImageBuildSettings
        {
            NoCache = true,
            Pull = true,
            Compress = true,
            File = dockerfile,
            ForceRm = true,
            Rm = true,
            BuildArg =
            [
                $"TFM={framework.TargetFramework}",
                $"DOTNET_VERSION={framework.RuntimeVersion}",
                $"UBUNTU_CODENAME={framework.UbuntuCodename}"
            ],
            Tag =
            [
                $"{image}:latest-{framework.TargetFramework}",
                $"{image}:{version}-{framework.TargetFramework}"
            ]
        };
    }

    private static string ImageName(string dockerfile)
    {
        var path = Path.GetFileName(dockerfile.Replace('\\', '/'));
        if (path.EndsWith(".dockerfile", System.StringComparison.OrdinalIgnoreCase))
        {
            path = path[..^".dockerfile".Length];
        }

        // "Dockerfile.unified.postgres" -> "unified-postgres"
        path = path.Replace("Dockerfile", string.Empty).Trim('.');
        path = path.Replace('.', '-');
        return $"opencertserver-appliance-{path}";
    }
}
