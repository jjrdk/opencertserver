namespace OpenCertServer.Tpm.Tests;

using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;

/// <summary>
/// Wraps an IBM Software TPM2 simulator running in a Docker container.
/// One container instance is shared for the whole feature (started by <see cref="TpmContainerHooks"/>)
/// and reused across all scenarios; TPM handle operations are idempotent so state does not bleed between scenarios.
/// </summary>
internal sealed class TpmSimulatorContainer : IAsyncDisposable
{
    private const int TpmCommandPort = 2321;
    private const int TpmPlatformPort = 2322;

    // Fixed tag so Docker caches the built image across test runs.
    private const string ImageTag = "opencertserver-ibmtpm2sim:test";

    private readonly IContainer _container;

    private TpmSimulatorContainer(IContainer container) => _container = container;

    /// <summary>
    /// Builds (or reuses the cached) IBM TPM2 simulator image, starts a fresh container,
    /// and waits until port 2321 is ready to accept connections.
    /// </summary>
    public static async Task<TpmSimulatorContainer> CreateAsync(CancellationToken ct = default)
    {
        // The Dockerfile is copied next to the test assembly by the .csproj CopyToOutputDirectory rule.
        var dockerfileDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;

        var image = new ImageFromDockerfileBuilder()
            .WithDockerfileDirectory(dockerfileDir)
            .WithDockerfile("Dockerfile.tpm2sim")
            .WithName(ImageTag)
            .Build();

        // Build only if the image doesn't exist yet; subsequent calls are instant.
        await image.CreateAsync(ct);

        var container = new ContainerBuilder(image)
            .WithPortBinding(TpmCommandPort, true)
            .WithPortBinding(TpmPlatformPort, true)
            .WithWaitStrategy(
                Wait.ForUnixContainer()
                    .UntilInternalTcpPortIsAvailable(TpmCommandPort))
            .Build();

        await container.StartAsync(ct);
        return new TpmSimulatorContainer(container);
    }

    /// <summary>Container hostname (always "localhost" on Desktop Docker).</summary>
    public string Host => _container.Hostname;

    /// <summary>Mapped host port for the TPM command channel (2321 inside the container).</summary>
    public int Port => _container.GetMappedPublicPort(TpmCommandPort);

    /// <summary>Mapped host port for the TPM platform channel (2322 inside the container).</summary>
    public int PlatformPort => _container.GetMappedPublicPort(TpmPlatformPort);

    /// <summary>
    /// Returns a <see cref="TpmCaOptions"/> pre-configured to talk to this container's TPM.
    /// Both the command and platform ports are set explicitly to their independently-mapped
    /// host port values (Testcontainers does not guarantee platform port == command port + 1).
    /// </summary>
    public TpmCaOptions CreateOptions(
        uint rsaKeyHandle = 0x81010001,
        uint ecDsaKeyHandle = 0x81010002) => new()
    {
        Mode = TpmMode.Simulator,
        SimulatorHost = Host,
        SimulatorPort = Port,
        SimulatorPlatformPort = PlatformPort,
        CaSubjectName = $"CN=tpm-test-ca-{Guid.NewGuid():N}",
        RsaKeyHandle = rsaKeyHandle,
        EcDsaKeyHandle = ecDsaKeyHandle,
        CaCertificateValidity = TimeSpan.FromDays(1),
        IssuedCertificateValidity = TimeSpan.FromHours(1),
    };

    public async ValueTask DisposeAsync() => await _container.DisposeAsync();
}

