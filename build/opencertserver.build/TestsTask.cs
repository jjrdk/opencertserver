using System.Linq;

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
            foreach (var framework in new[] { "net10.0", "net11.0" })
            {
                var reportName = Path.GetFullPath($"./artifacts/testreports/{context.BuildVersion}_{filename}_{framework}.xml");
                context.Log.Information("Test report: {0}", reportName);

                var coreTestSettings = new DotNetRunSettings
                {
                    NoBuild = true,
                    NoRestore = true,
                    Configuration = context.BuildConfiguration,
                    Framework = framework,
                    ArgumentCustomization = x => x.Append("--").AppendSwitchQuoted("-result-xml", reportName)
                };

                context.DotNetRun(project.FullPath, coreTestSettings);
            }
        }
    }
}
