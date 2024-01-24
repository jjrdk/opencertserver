namespace OpenCertServer.Build;

using Cake.Common.IO;
using Cake.Common.Tools.DotNet;
using Cake.Common.Tools.DotNet.Test;
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

        foreach (var project in projects)
        {
            context.Log.Information("Testing: {0}", project.FullPath);
            var filename = Path.GetFileNameWithoutExtension(project.FullPath).Replace('.', '_');
            var reportName = Path.GetFullPath($"./artifacts/testreports/{context.BuildVersion}_{filename}.xml");

            context.Log.Information($"{reportName}", reportName);

            var coreTestSettings = new DotNetTestSettings
            {
                NoBuild = true,
                NoRestore = true,
                // Set configuration as passed by command line
                Configuration = context.BuildConfiguration,
                ArgumentCustomization = x => x.Append("--logger \"trx;LogFileName=" + reportName + "\"")
            };

            context.DotNetTest(project.FullPath, coreTestSettings);
        }
    }
}
