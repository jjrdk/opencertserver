namespace OpenCertServer.Build;

using Cake.Common.Tools.DotNet;
using Cake.Common.Tools.DotNet.MSBuild;
using Cake.Common.Tools.DotNet.Pack;
using Cake.Core.Diagnostics;
using Cake.Frosting;
using System.IO;

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
            MSBuildSettings = new DotNetMSBuildSettings()
                .SetConfiguration(context.BuildConfiguration)
                .SetVersion(context.BuildVersion)
        };
        string[] projectNames =
        [
            "CertesSlim",
            "opencertserver.acme.abstractions",
            "opencertserver.acme.aspnetclient",
            "opencertserver.acme.remote",
            "opencertserver.acme.server",
            "opencertserver.acme.yarp",
            "OpenCertServer.Amd.Native",
            "OpenCertServer.Sgx.Native",
            "opencertserver.attestation",
            "opencertserver.ca",
            "opencertserver.ca.client",
            "opencertserver.ca.protocol",
            "opencertserver.ca.server",
            "opencertserver.ca.utils",
            "opencertserver.contrib.intune",
            "opencertserver.data",
            "opencertserver.data.mssql",
            "opencertserver.data.postgresql",
            "opencertserver.est.client",
            "opencertserver.est.server",
            "opencertserver.ra",
            "opencertserver.scep.server",
            "opencertserver.tss.net",
            "opencertserver.tpm"
        ];
        foreach (var projectName in projectNames)
        {
            var projectDirectory = Path.Combine("src", projectName);
            var (pack, symbols) = GetPackOptions(projectName, projectDirectory);
            if (!pack)
            {
                context.Log.Warning(
                    "Skipping {0}: no native runtime assets are staged in {1}. Existing packages in the output directory are not removed.",
                    projectName, projectDirectory);
                continue;
            }

            packSettings.IncludeSymbols = symbols;
            context.DotNetPack(Path.Combine(projectDirectory, $"{projectName}.csproj"), packSettings);
        }
    }

    internal static (bool Pack, bool Symbols) GetPackOptions(string projectName, string projectDirectory)
    {
        var nativeLibrary = projectName switch
        {
            "OpenCertServer.Amd.Native" => "amd_snp_driver.so",
            "OpenCertServer.Sgx.Native" => "libsgx_dcap_ql.so",
            _ => null
        };
        if (nativeLibrary is null)
        {
            return (true, true);
        }

        var hasNativeAsset = File.Exists(Path.Combine(projectDirectory, "runtimes", "linux-x64", "native", nativeLibrary))
            || File.Exists(Path.Combine(projectDirectory, "runtimes", "linux-arm64", "native", nativeLibrary));
        return (hasNativeAsset, false);
    }
}
