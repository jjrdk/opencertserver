using Cake.Common.Tools.DotNet;
using Cake.Common.Tools.DotNet.Publish;
using Cake.Docker;
using Cake.Frosting;

namespace OpenCertServer.Build;

/// <summary>
/// Publishes every per-role host and builds its appliance images, tagging each with the same
/// <see cref="BuildContext.BuildVersion"/> the rest of the build uses.
///
/// Each appliance Dockerfile now COPYs the publish of its own host project, so the publish is
/// per-role (not a single shared certserver binary):
///   - ca       -> artifacts/publish/ca/&lt;rid&gt;/       + artifacts/publish/ca/mssql/&lt;rid&gt;/
///   - ra       -> artifacts/publish/ra/&lt;rid&gt;/       + artifacts/publish/ra/mssql/&lt;rid&gt;/
///   - unified  -> artifacts/publish/unified/&lt;rid&gt;/  + artifacts/publish/unified/mssql/&lt;rid&gt;/
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
    private sealed record RoleSpec(string Name, string Project, string[] BaseDockerfiles, string[] MssqlDockerfiles);

    // One entry per role host. The base+postgres Dockerfiles COPY from .../&lt;role&gt;/&lt;rid&gt;/
    // (invariant); the mssql Dockerfiles COPY from .../&lt;role&gt;/mssql/&lt;rid&gt;/ (no invariant).
    private static readonly RoleSpec[] Roles =
    {
        new("ca", "./src/hosts/opencertserver.host.ca/opencertserver.host.ca.csproj",
            ["./Dockerfile.ca", "./Dockerfile.ca.postgres"],
            ["./Dockerfile.ca.mssql"]),
        new("ra", "./src/hosts/opencertserver.host.ra/opencertserver.host.ra.csproj",
            ["./Dockerfile.ra", "./Dockerfile.ra.postgres"],
            ["./Dockerfile.ra.mssql"]),
        // Dockerfile.appliance is the unified alias (same COPY path as Dockerfile.unified).
        new("unified", "./src/hosts/opencertserver.host.unified/opencertserver.host.unified.csproj",
            ["./Dockerfile.unified", "./Dockerfile.appliance", "./Dockerfile.unified.postgres"],
            ["./Dockerfile.unified.mssql"]),
    };

    public override void Run(BuildContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        foreach (var role in Roles)
        {
            // 1) base + postgres images: InvariantGlobalization publish (chiseled runtime, no ICU).
            //    The image sets DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1, so the publish is made
            //    invariant via DOTNET_CLI_INVARIANT=true (equivalent to -p:InvariantGlobalization=true).
            System.Environment.SetEnvironmentVariable("DOTNET_CLI_INVARIANT", "true");
            try
            {
                context.DotNetPublish(role.Project, new DotNetPublishSettings
                {
                    PublishTrimmed = false,
                    Runtime = "linux-x64",
                    SelfContained = true,
                    Framework = "net10.0",
                    Configuration = context.BuildConfiguration,
                    OutputDirectory = $"./artifacts/publish/{role.Name}/linux-x64/"
                });

                foreach (var dockerfile in role.BaseDockerfiles)
                {
                    BuildImage(context, dockerfile, role.Name);
                }
            }
            finally
            {
                System.Environment.SetEnvironmentVariable("DOTNET_CLI_INVARIANT", null);
            }

            // 2) mssql image: published WITHOUT invariant globalization (the SQL Server EF Core
            //    provider requires ICU, which the chiseled runtime does not provide, so these
            //    images use the full runtime-deps base).
            context.DotNetPublish(role.Project, new DotNetPublishSettings
            {
                PublishTrimmed = false,
                Runtime = "linux-x64",
                SelfContained = true,
                Framework = "net10.0",
                Configuration = context.BuildConfiguration,
                OutputDirectory = $"./artifacts/publish/{role.Name}/mssql/linux-x64/"
            });

            foreach (var dockerfile in role.MssqlDockerfiles)
            {
                BuildImage(context, dockerfile, role.Name);
            }
        }
    }

    // Builds a single appliance image, tagging it :latest and with the build version.
    //
    //   Dockerfile.unified.postgres -> opencertserver-appliance-unified-postgres
    //   Dockerfile.ca               -> opencertserver-appliance-ca
    //   Dockerfile.appliance        -> opencertserver-appliance-appliance
    private static void BuildImage(BuildContext context, string dockerfile, string imagePrefix)
    {
        var image = ImageName(dockerfile, imagePrefix);
        context.DockerBuild(new DockerImageBuildSettings
        {
            NoCache = true,
            Pull = true,
            Compress = true,
            File = dockerfile,
            ForceRm = true,
            Rm = true,
            Tag = new[]
            {
                $"{image}:latest",
                $"{image}:{context.BuildVersion}"
            }
        }, "./");
    }

    private static string ImageName(string dockerfile, string prefix)
    {
        var path = dockerfile.Replace("\\", "/").TrimStart('.');
        if (path.EndsWith(".dockerfile", System.StringComparison.OrdinalIgnoreCase))
            path = path.Substring(0, path.Length - ".dockerfile".Length);
        // "Dockerfile.unified.postgres" -> "unified-postgres"
        path = path.Replace("Dockerfile", string.Empty).Trim('.');
        path = path.Replace('.', '-');
        return $"{prefix}-{path}";
    }
}
