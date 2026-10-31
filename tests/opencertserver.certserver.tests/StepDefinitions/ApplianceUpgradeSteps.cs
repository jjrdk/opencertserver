namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using OpenCertServer.Ca.Utils.Ca;
using Reqnroll;
using Xunit;

[Binding]
public sealed partial class ApplianceUpgradeSteps : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "opencert-appliance-" + Guid.NewGuid().ToString("N"));

    private string Source => Path.Combine(_directory, "source.json");
    private string Loaded => Path.Combine(_directory, "loaded.json");
    private Process? _server;
    private readonly List<string> _output = [];
    private int _port;
    private X509Certificate2? _certificate;
    private ApplianceCertificateStore? _store;
    private string? _container;

    public ApplianceUpgradeSteps() => Directory.CreateDirectory(_directory);

    [Given("a hardened CA appliance configuration file")]
    public void HardenedConfiguration()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        _port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create();
        var rsaRequest =
            new CertificateRequest("CN=Appliance RSA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var ecRequest = new CertificateRequest("CN=Appliance EC", ec, HashAlgorithmName.SHA256);
        WriteCa(rsaRequest, rsa.ExportPkcs8PrivateKeyPem(), "rsa");
        WriteCa(ecRequest, ec.ExportPkcs8PrivateKeyPem(), "ecdsa");
        using var tlsKey = RSA.Create(2048);
        var tlsRequest =
            new CertificateRequest("CN=localhost", tlsKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddDnsName("ca");
        names.AddDnsName("host.docker.internal");
        tlsRequest.CertificateExtensions.Add(names.Build());
        using var tls =
            tlsRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        File.WriteAllText(Path.Combine(_directory, "tls.pem"), tls.ExportCertificatePem());
        File.WriteAllText(Path.Combine(_directory, "tls.key"), tlsKey.ExportPkcs8PrivateKeyPem());
        var config = new JsonObject
        {
            ["version"] = 2,
            ["Appliance"] = new JsonObject { ["Hardened"] = true, ["Role"] = "Ca", ["DataDirectory"] = _directory },
            ["Jwt"] = new JsonObject
                { ["Authority"] = "https://identity.example.test", ["Audiences"] = new JsonArray("appliance") },
            ["port"] = _port,
            ["AllowedHosts"] = "localhost",
            ["rsa"] = new JsonObject
                { ["Pem"] = Path.Combine(_directory, "rsa.pem"), ["KeyPem"] = Path.Combine(_directory, "rsa.key") },
            ["ecdsa"] = new JsonObject
                { ["Pem"] = Path.Combine(_directory, "ecdsa.pem"), ["KeyPem"] = Path.Combine(_directory, "ecdsa.key") },
            ["Kestrel"] = new JsonObject
            {
                ["Certificates"] = new JsonObject
                {
                    ["Default"] = new JsonObject
                    {
                        ["Path"] = Path.Combine(_directory, "tls.pem"),
                        ["KeyPath"] = Path.Combine(_directory, "tls.key")
                    }
                }
            }
        };
        File.WriteAllText(Source, config.ToJsonString());
    }

    [Given("a hardened RA appliance configuration file")]
    public void RaConfiguration()
    {
        HardenedConfiguration();
        var config = ApplianceConfiguration.ReadDocument(Source);
        config["Appliance"]!["Role"] = "Ra";
        config.Remove("rsa");
        config.Remove("ecdsa");
        config["Ra"] = new JsonObject
        {
            ["PeerUrl"] = "https://ca.example.test/",
            ["Scope"] = "tenant.example.test",
            ["Profile"] = "rsa",
            ["ClientCertificatePath"] = Path.Combine(_directory, "tls.pem"),
            ["ClientPrivateKeyPath"] = Path.Combine(_directory, "tls.key")
        };
        File.WriteAllText(Source, config.ToJsonString());
        File.Delete(Path.Combine(_directory, "rsa.key"));
        File.Delete(Path.Combine(_directory, "ecdsa.key"));
    }

    [Given("a hardened unified appliance configuration file")]
    public void UnifiedConfiguration()
    {
        HardenedConfiguration();
        var config = ApplianceConfiguration.ReadDocument(Source);
        config["Appliance"]!["Role"] = "Unified";
        config["AcmeServer"] = new JsonObject
        {
            ["ExternalAccountRequired"] = true,
            ["CAAIdentities"] = new JsonArray("localhost"),
            ["HostedWorkers"] = new JsonObject
            {
                ["EnableValidationService"] = true,
                ["EnableIssuanceService"] = true
            }
        };
        ConfigureExternalAccountKey(config);
        File.WriteAllText(Source, config.ToJsonString());
    }

    private void WriteCa(CertificateRequest request, string key, string name)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var certificate =
            request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
        File.WriteAllText(Path.Combine(_directory, name + ".pem"), certificate.ExportCertificatePem());
        File.WriteAllText(Path.Combine(_directory, name + ".key"), key);
    }

    [When("the appliance starts without certificate command line arguments")]
    public async Task Start()
    {
        var image = Environment.GetEnvironmentVariable("OPENCERT_APPLIANCE_TEST_IMAGE");
        Assert.SkipWhen(OperatingSystem.IsMacOS() && string.IsNullOrWhiteSpace(image),
            "macOS SslStream does not support TLS 1.3; set OPENCERT_APPLIANCE_TEST_IMAGE to a built Linux image.");
        if (!string.IsNullOrWhiteSpace(image))
        {
            await StartContainer(image);
            return;
        }

        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = _directory,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("exec");
        start.ArgumentList.Add("--runtimeconfig");
        start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory,
            "opencertserver.certserver.tests.runtimeconfig.json"));
        start.ArgumentList.Add(typeof(Program).Assembly.Location);
        start.ArgumentList.Add("--config");
        start.ArgumentList.Add(Source);
        start.Environment.Remove("OPENCERT_CONFIG");
        _server = new Process { StartInfo = start };
        _server.OutputDataReceived += (_, args) =>
        {
            if (args.Data is { } line)
                lock (_output)
                    _output.Add(line);
        };
        _server.ErrorDataReceived += (_, args) =>
        {
            if (args.Data is { } line)
                lock (_output)
                    _output.Add(line);
        };
        Assert.True(_server.Start());
        _server.BeginOutputReadLine();
        _server.BeginErrorReadLine();
        string? lastError = null;
        for (var attempt = 0; attempt < 100; attempt++)
        {
            if (_server.HasExited)
            {
                Assert.Fail(string.Join(Environment.NewLine, _output));
            }

            var response = await Probe("/health", SslProtocols.Tls13);
            if (response.Status == 200) return;
            lastError = response.Error;

            await Task.Delay(100);
        }

        Assert.Fail($"Appliance failed to become ready: {lastError}\n" + string.Join(Environment.NewLine, _output));
    }

    private async Task StartContainer(string image)
    {
        var config = ApplianceConfiguration.ReadDocument(Source);
        var role = config["Appliance"]!["Role"]!.GetValue<string>();
        config["port"] = 5001;
        config["Appliance"]!["DataDirectory"] = "/var/lib/opencertserver";
        File.WriteAllText(Source, config.ToJsonString().Replace(_directory, "/run/secrets", StringComparison.Ordinal));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(_directory, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        _container = "opencert-appliance-" + Guid.NewGuid().ToString("N");
        var arguments = new List<string>
        {
            "run", "--detach", "--name", _container, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--tmpfs", "/var/lib/opencertserver:rw,uid=1654,gid=1654",
            "--publish", $"127.0.0.1:{_port}:5001", "--env", $"Appliance__Role={role}",
            "--env", "SSL_CERT_FILE=/run/secrets/tls.pem",
            "--add-host", "host.docker.internal:host-gateway",
            "--mount", $"type=bind,src={Source},dst=/config/appsettings.json,readonly"
        };
        if (_network != null)
            arguments.AddRange(["--network", _network, "--network-alias", role.ToLowerInvariant()]);
        foreach (var file in Directory.GetFiles(_directory)
            .Where(path => path.EndsWith(".pem") || path.EndsWith(".key")))
        {
            if (role == "Ra" && Path.GetFileName(file) is "rsa.key" or "ecdsa.key") continue;
            arguments.Add("--mount");
            arguments.Add($"type=bind,src={file},dst=/run/secrets/{Path.GetFileName(file)},readonly");
        }

        arguments.Add(image);
        var result = await Execute("docker", arguments);
        Assert.True(result.ExitCode == 0, result.Error);
        for (var attempt = 0; attempt < 100; attempt++)
        {
            if ((await Probe("/health", SslProtocols.Tls13)).Status == 200) return;
            await Task.Delay(100);
        }

        var logs = await Execute("docker", ["logs", _container]);
        Assert.Fail("Native appliance did not become ready: " + logs.Output + logs.Error);
    }

    private async Task<(int ExitCode, int Status, string Error)> Probe(
        string path,
        SslProtocols protocols,
        string? method = null)
    {
        var protocol = protocols == SslProtocols.Tls13 ? "1.3" : "1.2";
        var arguments = new List<string>
        {
            "--silent", "--show-error", "--noproxy", "*", "--connect-timeout", "2", "--max-time", "5",
            "--cacert", Path.Combine(_directory, "tls.pem"), "--tlsv" + protocol, "--tls-max", protocol,
            "--output", OperatingSystem.IsWindows() ? "NUL" : "/dev/null", "--write-out", "%{http_code}"
        };
        if (method != null) arguments.AddRange(["--request", method]);
        arguments.Add($"https://localhost:{_port}{path}");
        var result = await Execute("curl", arguments);
        return (result.ExitCode, int.TryParse(result.Output, out var status) ? status : 0, result.Error);
    }

    private static async Task<(int ExitCode, string Output, string Error)> Execute(
        string command,
        IEnumerable<string> arguments)
    {
        var start = new ProcessStartInfo(command) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {command}.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, await output, await error);
    }

    [Then("the appliance health endpoint accepts TLS 1.3")]
    public async Task Health()
    {
        var response = await Probe("/health", SslProtocols.Tls13);
        Assert.True(response.ExitCode == 0, response.Error);
        Assert.Equal(200, response.Status);
    }

    [Then("the appliance rejects TLS 1.2")]
    public async Task RejectTls12()
    {
        var response = await Probe("/health", SslProtocols.Tls12);
        Assert.NotEqual(0, response.ExitCode);
        Assert.Equal(0, response.Status);
    }

    [Then("the CA-only appliance does not expose EST or ACME")]
    public async Task NoEnrollment()
    {
        foreach (var path in new[] { "/.well-known/est/cacerts", "/directory" })
        {
            var response = await Probe(path, SslProtocols.Tls13);
            Assert.Equal(404, response.Status);
        }
    }

    [Then("the RA requires an authenticated operator")]
    public async Task RaRequiresOperator()
    {
        var response = await Probe("/ra/enroll", SslProtocols.Tls13, "POST");
        Assert.Equal(401, response.Status);
        Assert.Equal(404, (await Probe("/ca/crl", SslProtocols.Tls13)).Status);
    }

    [Then("the unified appliance exposes CA, EST and ACME")]
    public async Task UnifiedEndpoints()
    {
        foreach (var path in new[] { "/ca/crl", "/.well-known/est/cacerts", "/directory" })
        {
            var response = await Probe(path, SslProtocols.Tls13);
            Assert.True(response.Status == 200, $"{path} returned {response.Status}: {response.Error}");
        }
    }

    [Given("a version 1 appliance configuration store")]
    public void PreviousVersion() => File.WriteAllText(Source,
        """{"version":1,"authority":"https://identity.example.test","audience":"ca,ra","Appliance":{"Role":"Ca"}}""");

    [When("the configuration is loaded into a new versioned store")]
    public void Load() => Assert.True(ApplianceConfiguration.RunCommand(["configload", Source, Loaded]));

    [Then("the store has version 2 and grouped JWT settings")]
    public void CurrentVersion()
    {
        var document = ApplianceConfiguration.ReadDocument(Loaded);
        Assert.Equal(2, document["version"]!.GetValue<int>());
        Assert.Null(document["authority"]);
        Assert.Equal("https://identity.example.test", document["Jwt"]!["Authority"]!.GetValue<string>());
        Assert.Equal(2, document["Jwt"]!["Audiences"]!.AsArray().Count);
    }

    [Then("configdump and configload round-trip the upgraded store")]
    public void RoundTrip()
    {
        var dump = Path.Combine(_directory, "dump.json");
        var roundTrip = Path.Combine(_directory, "roundtrip.json");
        Assert.True(ApplianceConfiguration.RunCommand(["configdump", Loaded, dump]));
        Assert.True(ApplianceConfiguration.RunCommand(["configload", dump, roundTrip]));
        Assert.True(JsonNode.DeepEquals(ApplianceConfiguration.ReadDocument(Loaded),
            ApplianceConfiguration.ReadDocument(roundTrip)));
        Assert.Throws<IOException>(() => ApplianceConfiguration.RunCommand(["configload", dump, roundTrip]));
    }

    [Then("startup rejects the old store without automatic migrations")]
    public void RejectOld() => Assert.Throws<InvalidOperationException>(() =>
        MigrationRunner.Upgrade(ApplianceConfiguration.ReadDocument(Source), false));

    [Then("automatic migration does not rewrite the mounted file")]
    public void ReadOnlyMigration()
    {
        var original = File.ReadAllText(Source);
        var configuration = new ConfigurationManager();
        configuration["config"] = Source;
        configuration["Migration:AutoApply"] = "true";
        ApplianceConfiguration.AddMountedConfiguration(configuration, []);
        Assert.Equal("2", configuration["version"]);
        Assert.Equal(original, File.ReadAllText(Source));
    }

    [Then("an unsupported appliance configuration version is rejected")]
    public void RejectFuture() => Assert.Throws<InvalidDataException>(() =>
        MigrationRunner.Upgrade(new JsonObject { ["version"] = 999 }, true));

    [Then("a hardened appliance rejects disabled CAA checks")]
    public void RejectBypass()
    {
        var configuration = new ConfigurationManager();
        configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Appliance:Hardened"] = "true", ["Appliance:DataDirectory"] = _directory,
            ["AcmeServer:DisableCaaChecks"] = "true"
        });
        Assert.Throws<InvalidOperationException>(() => ApplianceOptions.Read(configuration));
    }

    [Given("a persistent appliance certificate store")]
    public void PersistentStore() => _store = new ApplianceCertificateStore(_directory);

    [When("a certificate is issued and revoked in the store")]
    public async Task IssueAndRevoke()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=persistent", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        _certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        await _store!.AddCertificate(_certificate);
        Assert.True(await _store.RemoveCertificate(_certificate.SerialNumber, X509RevocationReason.KeyCompromise));
        _store.Dispose();
        _store = null;
    }

    [Then("the reopened store retains the certificate and revocation")]
    public async Task Reopen()
    {
        _store = new ApplianceCertificateStore(_directory);
        var items = await _store.GetInventory().ToArrayAsync();
        var item = Assert.Single(items);
        Assert.Equal(_certificate!.Thumbprint, item.Thumbprint);
        Assert.Equal(X509RevocationReason.KeyCompromise, item.RevocationReason);
        Assert.Single(await _store.GetRevocationList().ToArrayAsync());
    }

    public void Dispose()
    {
        if (_server is { HasExited: false }) _server.Kill(entireProcessTree: true);
        _server?.WaitForExit();
        _server?.Dispose();
        _store?.Dispose();
        _certificate?.Dispose();
        if (_container != null)
            Execute("docker", ["rm", "--force", _container]).GetAwaiter().GetResult();
        DisposeRaTopology();
        Directory.Delete(_directory, recursive: true);
    }
}
