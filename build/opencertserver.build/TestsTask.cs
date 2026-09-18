namespace OpenCertServer.Build;

using Cake.Common.Tools.DotNet.Run;
using System.IO;
using Cake.Common.IO;
using Cake.Common.Tools.DotNet;
using Cake.Core;
using Cake.Core.Diagnostics;
using Cake.Frosting;

[TaskName("Tests")]
[IsDependentOn(typeof(BuildTask))]
public sealed class TestsTask : FrostingTask<BuildContext>
{
    /// <inheritdoc />
    public override void Run(BuildContext context)
    {
        context.Log.Information("Ensuring test report output");
        context.EnsureDirectoryExists(
            context.Environment.WorkingDirectory.Combine("artifacts").Combine("testreports"));

        var projects = context.GetFiles("./tests/**/*.tests.csproj");

        foreach (var project in projects.Where(p => !p.FullPath.Contains("tpm") && !p.FullPath.Contains("mcp")))
        {
            context.Log.Information("Testing: {0}", project.FullPath);
            var filename = Path.GetFileNameWithoutExtension(project.FullPath).Replace('.', '_');
            var reportName = Path.GetFullPath($"./artifacts/testreports/{context.BuildVersion}_{filename}.xml");

            context.Log.Information($"{reportName}", reportName);

            var coreTestSettings = new DotNetRunSettings
            {
                NoBuild = true,
                NoRestore = true,
                // Set configuration as passed by command line
                Configuration = context.BuildConfiguration,
                ArgumentCustomization = x => x.Append("--").AppendSwitchQuoted("-result-xml", reportName)
            };

            context.DotNetRun(project.FullPath, coreTestSettings);
        }
    }
}
