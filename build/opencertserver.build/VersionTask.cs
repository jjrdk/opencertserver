namespace OpenCertServer.Build;

using System;
using System.Text.Json;
using Cake.Common;
using Cake.Core;
using Cake.Core.Diagnostics;
using Cake.Core.IO;
using Cake.Frosting;

[TaskName("Version")]
[TaskDescription("Retrieves the current version from the git repository")]
public sealed class VersionTask : FrostingTask<BuildContext>
{
    public override void Run(BuildContext context)
    {
        var tool = context.Tools.Resolve(["dotnet-gitversion", "dotnet-gitversion.exe"])
         ?? throw new CakeException("GitVersion tool was not found.");
        var exitCode = context.StartProcess(tool, new ProcessSettings
        {
            Arguments = "--output json --no-normalize",
            RedirectStandardOutput = true
        }, out var output);
        if (exitCode != 0)
        {
            throw new CakeException($"GitVersion failed with exit code {exitCode}.");
        }

        using var versionInfo = JsonDocument.Parse(string.Join(Environment.NewLine, output));
        var root = versionInfo.RootElement;
        var branch = root.GetProperty("BranchName").GetString()
         ?? throw new CakeException("GitVersion did not return a branch name.");
        var version = root.GetProperty("MajorMinorPatch").GetString()
         ?? throw new CakeException("GitVersion did not return a version.");
        var distance = root.GetProperty("VersionSourceDistance").GetInt32();
        var fullVersion = root.GetProperty("FullSemVer").GetString()
         ?? throw new CakeException("GitVersion did not return a full version.");

        context.BuildVersion = FormatBuildVersion(branch, version, distance);

        context.InformationalVersion = $"{version}.{distance}";
        context.Log.Information("Build configuration: {0}", context.BuildConfiguration);
        context.Log.Information("Branch: {0}", branch);
        context.Log.Information("Version: {0}", fullVersion);
        context.Log.Information("Version: {0}", version);
        context.Log.Information("Build version: {0}", context.BuildVersion);
        context.Log.Information("Informational version: {0}", context.InformationalVersion);
        context.Log.Information("VersionSourceDistance: {0}", distance);
    }

    internal static string FormatBuildVersion(string branch, string version, int distance)
    {
        if (branch == "master" || branch.StartsWith("tags/", StringComparison.Ordinal))
        {
            return version;
        }

        if (branch.StartsWith("beta/", StringComparison.Ordinal))
        {
            return $"{branch[(branch.IndexOf('/') + 1)..]}-{distance}";
        }

        return $"{version}-{branch[(branch.IndexOf('/') + 1)..]}.{distance}";
    }
}
