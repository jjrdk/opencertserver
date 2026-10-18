namespace OpenCertServer.Iq.Tests.Support;

using System.Text;
using System.Text.Json;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Images;

/// <summary>Runs the published MCP host as a subprocess of the existing Linux IQ client.</summary>
internal sealed class IqMcpEnvironment : IAsyncDisposable
{
    private readonly IContainer _client;

    public IqMcpEnvironment(IImage clientImage, string publishDirectory)
    {
        _client = new ContainerBuilder(clientImage)
            .WithResourceMapping(new DirectoryInfo(publishDirectory), "/opt/iq-mcp", fileMode: Unix.FileMode755)
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(RepositoryPaths.IqProject, "client", "scripts", "mcp-stdio.py")),
                "/usr/local/bin/mcp-stdio.py",
                fileMode: Unix.FileMode644)
            .WithEntrypoint("python3", "/usr/local/bin/mcp-stdio.py", "serve")
            .WithWaitStrategy(Wait.ForUnixContainer().UntilCommandIsCompleted(
                ["test", "-S", "/tmp/iq-mcp.sock"], wait => wait.WithTimeout(TimeSpan.FromSeconds(30))))
            .Build();
    }

    public Task StartAsync() => _client.StartAsync();

    public Task<ExecResult> ExecAsync(string script) => _client.ExecAsync(["bash", "-euo", "pipefail", "-c", script]);

    public async Task<JsonElement> ControlAsync(object command)
    {
        var encoded = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(command));
        var result = await ExecAsync($"python3 /usr/local/bin/mcp-stdio.py control '{encoded}'").ConfigureAwait(false);
        if (result.ExitCode != 0)
        {
            throw new InvalidOperationException($"MCP control failed ({result.ExitCode}):\n{result.Stdout}\n{result.Stderr}");
        }

        using var document = JsonDocument.Parse(result.Stdout);
        return document.RootElement.Clone();
    }

    public async Task<string> GetDiagnosticsAsync()
    {
        var logs = await _client.GetLogsAsync().ConfigureAwait(false);
        var files = await ExecAsync(
            "for f in /workspace/mcp.stderr /workspace/transcript.jsonl; do "
            + "if test -f \"$f\"; then echo \"===== $f =====\"; tail -c 20000 \"$f\"; fi; done")
            .ConfigureAwait(false);
        return new StringBuilder().AppendLine(logs.Stdout).AppendLine(logs.Stderr)
            .AppendLine(files.Stdout).AppendLine(files.Stderr).ToString();
    }

    public ValueTask DisposeAsync() => _client.DisposeAsync();
}
