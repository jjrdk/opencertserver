using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;

namespace OpenCertServer.CertServer.Tests.Support;

using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Hosts an OpenTelemetry Collector container for acceptance tests.
/// </summary>
internal sealed class OpenTelemetryCollectorContainer : IAsyncDisposable
{
    private const ushort OtlpGrpcPort = 4317;
    private const ushort OtlpHttpPort = 4318;
    private const ushort PrometheusPort = 9464;
    private readonly IContainer _container;
    private readonly HttpClient _httpClient = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="OpenTelemetryCollectorContainer"/> class.
    /// </summary>
    public OpenTelemetryCollectorContainer()
    {
        var configPath = ResolveConfigPath();
        _container = new ContainerBuilder("otel/opentelemetry-collector-contrib:latest")
            .WithName($"dotauth-otel-{Guid.NewGuid():N}")
            .WithPortBinding(OtlpGrpcPort, true)
            .WithPortBinding(OtlpHttpPort, true)
            .WithPortBinding(PrometheusPort, true)
            .WithResourceMapping(new FileInfo(configPath), "/etc/otelcol-contrib/")
            .WithCommand("--config=/etc/otelcol-contrib/otel-collector-config.yaml")
            .WithWaitStrategy(
                Wait.ForUnixContainer()
                    .UntilMessageIsLogged("Everything is ready"))
            .Build();
    }

    /// <summary>
    /// Gets the OTLP gRPC endpoint that the server should export telemetry to.
    /// </summary>
    public Uri OtlpGrpcEndpoint => new($"http://localhost:{_container.GetMappedPublicPort(OtlpGrpcPort)}");

    /// <summary>
    /// Gets the Prometheus scrape endpoint exposed by the collector.
    /// </summary>
    public Uri PrometheusEndpoint => new($"http://localhost:{_container.GetMappedPublicPort(PrometheusPort)}/metrics");

    /// <summary>
    /// Gets the OTLP HTTP endpoint that the server can export telemetry to.
    /// </summary>
    public Uri OtlpHttpEndpoint => new($"http://localhost:{_container.GetMappedPublicPort(OtlpHttpPort)}");

    /// <summary>
    /// Starts the collector container.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(30));
        await _container.StartAsync(timeoutCts.Token).ConfigureAwait(false);
    }

    /// <summary>
    /// Reads the collector logs, which include exported traces via the debug exporter.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    public Task<string> ReadTracesAsync(CancellationToken cancellationToken = default)
    {
        return ReadLogsAsync(cancellationToken);
    }

    /// <summary>
    /// Reads the collector logs, which include exported metrics via the debug exporter.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    public Task<string> ReadMetricsAsync(CancellationToken cancellationToken = default)
    {
        return ReadLogsAsync(cancellationToken);
    }

    /// <summary>
    /// Reads the Prometheus metrics endpoint from the collector.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    public Task<string> ReadPrometheusMetricsAsync(CancellationToken cancellationToken = default)
    {
        return _httpClient.GetStringAsync(PrometheusEndpoint, cancellationToken);
    }

    /// <summary>
    /// Stops and disposes the collector container resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        await _container.DisposeAsync().ConfigureAwait(false);
        _httpClient.Dispose();
    }

    /// <summary>
    /// Reads the collector logs from the container.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The combined standard output and error logs.</returns>
    private async Task<string> ReadLogsAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var result = await _container
            .GetLogsAsync(DateTime.UnixEpoch, now, false, cancellationToken)
            .ConfigureAwait(false);

        return string.Concat(result.Stdout, Environment.NewLine, result.Stderr);
    }

    /// <summary>
    /// Resolves the collector configuration file from either the test output directory or the project support folder.
    /// </summary>
    /// <returns>The absolute config file path.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the collector config cannot be located.</exception>
    private static string ResolveConfigPath()
    {
        var outputPath = Path.Combine(AppContext.BaseDirectory, "otel-collector-config.yaml");
        if (File.Exists(outputPath))
        {
            return outputPath;
        }

        var projectPath = Path.GetFullPath(
            Path.Combine(AppContext.BaseDirectory, "../../../Support/otel-collector-config.yaml"));
        if (File.Exists(projectPath))
        {
            return projectPath;
        }

        throw new FileNotFoundException("The OpenTelemetry collector config file could not be found.", outputPath);
    }
}
