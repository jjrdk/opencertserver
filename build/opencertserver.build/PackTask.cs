namespace OpenCertServer.Build;

using Cake.Common.Tools.DotNet;
using Cake.Common.Tools.DotNet.MSBuild;
using Cake.Common.Tools.DotNet.Pack;
using Cake.Core.Diagnostics;
using Cake.Frosting;

[TaskName("Pack")]
[IsDependentOn(typeof(TestsTask))]
public sealed class PackTask : FrostingTask<BuildContext>
{
    /// <inheritdoc />
    public override void Run(BuildContext context)
    {
        context.Log.Information("Package version: {0}", context.BuildVersion);

        var packSettings = new DotNetPackSettings
        {
            Configuration = context.BuildConfiguration,
            NoBuild = true,
            SymbolPackageFormat = "snupkg",
            NoRestore = true,
            OutputDirectory = "./artifacts/packages",
            IncludeSymbols = true,
            MSBuildSettings = new DotNetMSBuildSettings().SetConfiguration(context.BuildConfiguration)
                .SetVersion(context.BuildVersion)
        };
        string[] projectNames =
        [
            "CertesSlim",
            "opencertserver.acme.abstractions",
            "opencertserver.acme.aspnetclient",
            "opencertserver.acme.server",
            "opencertserver.ca",
            "opencertserver.ca.utils",
            "opencertserver.est.client",
            "opencertserver.est.server",
            "opencertserver.ca.server",
            "opencertserver.tss.net",
            "opencertserver.tpm"
        ];
        foreach (var projectName in projectNames)
        {
            context.DotNetPack($"./src/{projectName}/{projectName}.csproj", packSettings);
        }
    }
}
