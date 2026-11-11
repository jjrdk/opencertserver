namespace OpenCertServer.Iq.Tests.Support;

using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Images;

/// <summary>
/// Builds the two images the IQ scenarios run: the OpenCertServer server image (the repository root
/// <c>Dockerfile</c> over a freshly published, self-contained server) and the Ubuntu client image
/// (<c>client/Dockerfile</c> over a freshly published <c>opencert</c> CLI). Both are built once per
/// test run for the Docker host's architecture, so the server runs natively instead of under emulation.
/// </summary>
/// <remarks>
/// Set <c>IQ_SERVER_IMAGE</c> / <c>IQ_CLIENT_IMAGE</c> to use prebuilt images instead (e.g. in CI), and
/// <c>IQ_DOCKER_ARCH</c> (<c>x64</c> or <c>arm64</c>) to override the detected architecture.
/// </remarks>
internal static class IqImages
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static IImage? _server;
    private static IImage? _client;
    private readonly record struct ApplianceRole(string Role, string Dockerfile);
    private static readonly Dictionary<string, ApplianceRole> ApplianceRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Unified"] = new("Unified", "Dockerfile.unified"),
        ["Ca"] = new("Ca", "Dockerfile.ca"),
        ["Ra"] = new("Ra", "Dockerfile.ra")
    };

    public static async Task<IImage> GetClientAsync(CancellationToken cancellationToken = default)
    {
        await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return _client ??= await BuildClientImage(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Gate.Release();
        }
    }

    public static Task PublishMcpAsync(string output, CancellationToken cancellationToken = default) =>
        DotNetPublish(
            Path.Combine(RepositoryPaths.Root, "src", "opencertserver.mcp", "opencertserver.mcp.csproj"),
            $"linux-{Arch}",
            output,
            cancellationToken,
            "-p:PublishTrimmed=false");

    public static async Task<(IImage Server, IImage Client)> GetAsync(CancellationToken cancellationToken = default)
    {
        await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _server ??= await BuildServerImage(cancellationToken).ConfigureAwait(false);
            _client ??= await BuildClientImage(cancellationToken).ConfigureAwait(false);
            return (_server, _client);
        }
        finally
        {
            Gate.Release();
        }
    }

    private static readonly Dictionary<string, IImage> _applianceImages = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, string> _applianceImageNames = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Builds one chiseled Ubuntu 24.04 appliance image (<c>Dockerfile.unified</c> / <c>Dockerfile.ca</c> /
    /// <c>Dockerfile.ra</c>) over a freshly published, self-contained server for the Docker host's
    /// architecture. The chiseled <c>runtime-deps</c> image carries the glibc native dependencies but no .NET
    /// runtime (and no chiseled ASP.NET Core image exists), so the server is published self-contained with the
    /// glibc RID (<c>linux-x64</c> / <c>linux-arm64</c>) and <c>InvariantGlobalization</c> — the framework and
    /// coreclr are bundled on top of the glibc deps. The same self-contained output is reused for all three
    /// roles; each role's Dockerfile only differs in the baked <c>Appliance__Role</c> default and exposed ports.
    /// </summary>
    public static async Task<(IImage Image, string Name)> GetApplianceImageAsync(
        string role, CancellationToken cancellationToken = default)
    {
        if (!ApplianceRoles.TryGetValue(role, out var applianceRole))
        {
            throw new ArgumentOutOfRangeException(nameof(role), role,
                "An appliance IQ role must be one of Unified, Ca, or Ra.");
        }

        await Gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_applianceImages.TryGetValue(role, out var image)
                && _applianceImageNames.TryGetValue(role, out var name))
            {
                return (image, name);
            }

            var built = await BuildApplianceImage(applianceRole, cancellationToken).ConfigureAwait(false);
            _applianceImages[role] = built.Image;
            _applianceImageNames[role] = built.Name;
            return built;
        }
        finally
        {
            Gate.Release();
        }
    }

    private static async Task<(IImage Image, string Name)> BuildApplianceImage(
        ApplianceRole applianceRole, CancellationToken cancellationToken)
    {
        var rid = $"linux-{Arch}";
        var imageName = $"opencertserver-iq-appliance-{applianceRole.Role.ToLowerInvariant()}:local";

        if (Environment.GetEnvironmentVariable($"IQ_APPLIANCE_{applianceRole.Role.ToUpperInvariant()}_IMAGE")
            is { Length: > 0 } prebuilt)
        {
            imageName = prebuilt;
            return (new DockerImage(prebuilt), imageName);
        }

        var context = Path.Combine(RepositoryPaths.IqArtifacts, $"appliance-context-{applianceRole.Role.ToLowerInvariant()}");
        Directory.CreateDirectory(context);
        File.Copy(Path.Combine(RepositoryPaths.Root, applianceRole.Dockerfile),
            Path.Combine(context, "Dockerfile"), true);

        // The self-contained publish is shared across the three role images; publish once per RID.
        var publishDir = Path.Combine(RepositoryPaths.IqArtifacts, "appliance-publish", rid);
        if (!File.Exists(Path.Combine(publishDir, "opencertserver.certserver")))
        {
            await DotNetPublish(
                    Path.Combine(RepositoryPaths.Root, "src", "opencertserver.certserver",
                        "opencertserver.certserver.csproj"),
                    rid,
                    publishDir,
                    cancellationToken,
                    "-p:InvariantGlobalization=true")
                .ConfigureAwait(false);
        }

        // The appliance Dockerfiles COPY artifacts/publish/appliance/${RID}/; stage the publish there.
        var stageDir = Path.Combine(context, "artifacts", "publish", "appliance", rid);
        if (Directory.Exists(stageDir))
        {
            Directory.Delete(stageDir, true);
        }

        Directory.CreateDirectory(stageDir);
        CopyRecursively(publishDir, stageDir);

        var image = new ImageFromDockerfileBuilder()
            .WithDockerfileDirectory(context)
            .WithDockerfile("Dockerfile")
            .WithName(imageName)
            .WithBuildArgument("PLATFORM", Platform)
            .WithBuildArgument("RID", rid)
            .WithImageBuildPolicy(PullPolicy.Always)
            .WithCleanUp(false)
            .Build();
        await image.CreateAsync(cancellationToken).ConfigureAwait(false);
        return (image, imageName);
    }


    private static string Arch =>
        Environment.GetEnvironmentVariable("IQ_DOCKER_ARCH")
        ?? (RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "arm64" : "x64");

    private static void CopyRecursively(string source, string destination)
    {
        var sourceDir = new DirectoryInfo(Path.GetFullPath(source));
        var destinationDir = new DirectoryInfo(Path.GetFullPath(destination));
        if (!destinationDir.Exists)
        {
            destinationDir.Create();
        }

        foreach (var file in sourceDir.EnumerateFiles("*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(sourceDir.FullName, file.FullName);
            var target = Path.Combine(destinationDir.FullName, relative);
            var targetDirectory = Path.GetDirectoryName(target);
            if (!string.IsNullOrEmpty(targetDirectory))
            {
                Directory.CreateDirectory(targetDirectory);
            }

            file.CopyTo(target, true);
        }
    }

    private static string Platform => Arch == "arm64" ? "linux/arm64" : "linux/amd64";

    private static async Task<IImage> BuildServerImage(CancellationToken cancellationToken)
    {
        if (Environment.GetEnvironmentVariable("IQ_SERVER_IMAGE") is { Length: > 0 } prebuilt)
        {
            return new DockerImage(prebuilt);
        }

        var rid = $"linux-musl-{Arch}";
        var context = Path.Combine(RepositoryPaths.IqArtifacts, "server-context");
        var publishDir = Path.Combine(context, "artifacts", "publish", "server", rid);
        await DotNetPublish(
                Path.Combine(RepositoryPaths.Root, "src", "opencertserver.certserver", "opencertserver.certserver.csproj"),
                rid,
                publishDir,
                cancellationToken)
            .ConfigureAwait(false);
        File.Copy(Path.Combine(RepositoryPaths.Root, "Dockerfile"), Path.Combine(context, "Dockerfile"), true);

        var image = new ImageFromDockerfileBuilder()
            .WithDockerfileDirectory(context)
            .WithDockerfile("Dockerfile")
            .WithName("opencertserver-iq-server:local")
            .WithBuildArgument("PLATFORM", Platform)
            .WithBuildArgument("RID", rid)
            .WithImageBuildPolicy(PullPolicy.Always)
            .WithCleanUp(false)
            .Build();
        await image.CreateAsync(cancellationToken).ConfigureAwait(false);
        return image;
    }

    private static async Task<IImage> BuildClientImage(CancellationToken cancellationToken)
    {
        if (Environment.GetEnvironmentVariable("IQ_CLIENT_IMAGE") is { Length: > 0 } prebuilt)
        {
            return new DockerImage(prebuilt);
        }

        var context = Path.Combine(RepositoryPaths.IqArtifacts, "client-context");
        var publishDir = Path.Combine(RepositoryPaths.IqArtifacts, "cli");
        await DotNetPublish(
                Path.Combine(RepositoryPaths.Root, "src", "opencertserver.cli", "opencertserver.cli.csproj"),
                $"linux-{Arch}",
                publishDir,
                cancellationToken,
                "-p:PublishSingleFile=true")
            .ConfigureAwait(false);
        Directory.CreateDirectory(context);
        File.Copy(Path.Combine(publishDir, "opencert"), Path.Combine(context, "opencert"), true);
        File.Copy(Path.Combine(RepositoryPaths.IqProject, "client", "Dockerfile"), Path.Combine(context, "Dockerfile"), true);
        File.Copy(Path.Combine(RepositoryPaths.IqProject, "client", "libest-compat.patch"),
            Path.Combine(context, "libest-compat.patch"), true);

        var image = new ImageFromDockerfileBuilder()
            .WithDockerfileDirectory(context)
            .WithDockerfile("Dockerfile")
            .WithName("opencertserver-iq-client:local")
            .WithImageBuildPolicy(PullPolicy.Always)
            .WithCleanUp(false)
            .Build();
        await image.CreateAsync(cancellationToken).ConfigureAwait(false);
        return image;
    }

    private static async Task DotNetPublish(
        string project,
        string rid,
        string output,
        CancellationToken cancellationToken,
        params string[] extra)
    {
        var info = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = RepositoryPaths.Root
        };
        foreach (var arg in (string[])
                 [
                     "publish", project, "-c", "Release", "-r", rid, "--self-contained", "-o", output, "-nologo",
                     "-v", "q", .. extra
                 ])
        {
            info.ArgumentList.Add(arg);
        }

        using var process = Process.Start(info) ?? throw new InvalidOperationException("Could not start dotnet publish.");
        var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"dotnet publish {project} -r {rid} failed ({process.ExitCode}):\n{await stdout.ConfigureAwait(false)}\n{await stderr.ConfigureAwait(false)}");
        }
    }
}
