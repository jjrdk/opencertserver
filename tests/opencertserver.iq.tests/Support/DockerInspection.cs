namespace OpenCertServer.Iq.Tests.Support;

using System.IO;
using System.Text.Json;
using Docker.DotNet;
using DotNet.Testcontainers.Configurations;

/// <summary>
/// Resolves the Docker Engine endpoint the way the <c>docker</c> CLI does (DOCKER_HOST, then the
/// current context's <c>meta.json</c>, then the well-known sockets) and inspects images and containers
/// through the Docker Engine HTTP API rather than shelling out to the CLI. The external <c>docker</c>
/// CLI's <c>inspect</c> is unreliable under the MTP/Docker-Desktop test host — it returns an empty user
/// with an exit code of 0 — whereas a native Docker.Engine client returns the real <c>Config.User</c>.
/// </summary>
internal static class DockerInspection
{
    /// <summary>Returns the <c>Config.User</c> of a running container, or null if unset.</summary>
    public static async System.Threading.Tasks.Task<string?> InspectContainerAsync(
        string containerName, System.Threading.CancellationToken cancellationToken = default)
    {
        var client = CreateClient();
        var inspected = await client.Containers.InspectContainerAsync(containerName, cancellationToken)
            .ConfigureAwait(false);
        return inspected.Config?.User;
    }

    /// <summary>Returns the <c>Config.User</c> baked into an image, or null if unset.</summary>
    public static async System.Threading.Tasks.Task<string?> InspectImageAsync(
        string imageName, System.Threading.CancellationToken cancellationToken = default)
    {
        var client = CreateClient();
        var inspected = await client.Images.InspectImageAsync(imageName, cancellationToken)
            .ConfigureAwait(false);
        return inspected.Config?.User;
    }

    static DockerClient CreateClient()
    {
        var builder = new DockerEndpointAuthenticationConfiguration(ResolveEndpoint()).GetDockerClientBuilder(
            System.Guid.NewGuid());
        return builder.Build();
    }

    /// <summary>Mirrors the Docker CLI's endpoint resolution so the probe works under MTP/Docker Desktop.</summary>
    static Uri ResolveEndpoint()
    {
        var dockerHost = System.Environment.GetEnvironmentVariable("DOCKER_HOST");
        if (!string.IsNullOrWhiteSpace(dockerHost))
        {
            return new Uri(dockerHost);
        }

        var userProfile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);
        var configPath = Path.Combine(userProfile, ".docker", "config.json");
        if (File.Exists(configPath))
        {
            using var document = JsonDocument.Parse(File.ReadAllText(configPath));
            var metaRoot = Path.Combine(userProfile, ".docker", "contexts", "meta");
            var context = document.RootElement.TryGetProperty("currentContext", out var current) &&
                          current.ValueKind == JsonValueKind.String
                ? current.GetString()
                : null;
            if (!string.IsNullOrEmpty(context))
            {
                var metaPath = Path.Combine(metaRoot, context, "meta.json");
                if (File.Exists(metaPath))
                {
                    using var meta = JsonDocument.Parse(File.ReadAllText(metaPath));
                    if (meta.RootElement.TryGetProperty("Endpoints", out var endpoints) &&
                        endpoints.TryGetProperty("docker", out var docker) &&
                        docker.TryGetProperty("Host", out var host) &&
                        host.GetString() is { } hostValue)
                    {
                        return new Uri(hostValue);
                    }
                }
            }
        }

        var runSocket = Path.Combine(userProfile, ".docker", "run", "docker.sock");
        if (File.Exists(runSocket))
        {
            return new Uri("unix://" + runSocket);
        }

        if (File.Exists("/var/run/docker.sock"))
        {
            return new Uri("unix:///var/run/docker.sock");
        }

        throw new System.InvalidOperationException(
            "Unable to resolve a Docker Engine endpoint for the IQ appliance user check.");
    }
}
