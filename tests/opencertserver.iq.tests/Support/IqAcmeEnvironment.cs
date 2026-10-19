namespace OpenCertServer.Iq.Tests.Support;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Docker.DotNet.Models;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Images;
using DotNet.Testcontainers.Networks;

/// <summary>
/// The black-box topology for deployment, ACME, CAA, EST, authority-information and CRL IQ (no compose file):
/// <list type="bullet">
/// <item>a private bridge network on a random /24 inside 198.18.0.0/15 (RFC 2544 benchmarking space), which
/// the server's http-01 SSRF guard does not block, unlike RFC 1918 ranges;</item>
/// <item>an authoritative test DNS server (<c>acme/dns_server.py</c>) for <c>example.com</c>, used by the
/// server through Docker's embedded resolver for http-01 lookups, CAA checks and dns-01 TXT reads;</item>
/// <item>the hardened OpenCertServer (<c>opencertserver</c>) with a separate test TLS certificate and
/// either a self-signed CA or file-backed issuing profiles;</item>
/// <item>the Debian client (<c>client</c>) running acme.sh, curl, openssl and jq.</item>
/// </list>
/// Only the server's HTTPS port and the DNS control API are published, on random host ports.
/// </summary>
internal sealed class IqAcmeEnvironment : IAsyncDisposable
{
    public const int ServerPort = 6001;
    public const int HttpPort = 6000;
    public const string ServerAlias = "opencertserver";
    public const string TosServerAlias = "opencertserver-tos";
    public const string ClientAlias = "client";
    public const string DnsAlias = "dns";
    public const string EabKeyId = "iq-eab";
    public const string CertbotEabKeyId = "iq-eab-certbot";
    public const string CaaIdentity = "iq.test";

    private const int DnsApiPort = 8080;
    private readonly List<IContainer> _containers = [];
    private INetwork _network = null!;
    private string _prefix = null!;
    private IImage _serverImage = null!;
    private IContainer _dns = null!;
    private IContainer _server = null!;
    private IContainer? _issuer;
    private IqAuthorityConfiguration? _authorityConfiguration;
    private IqRevocationConfiguration? _revocationConfiguration;
    private bool _disableCaaChecks;
    private bool _enableHttp;
    private bool _enableTelemetry;

    private IqAcmeEnvironment(TestTlsPki tls)
    {
        Tls = tls;
        EabHmacKey = Base64Url(RandomNumberGenerator.GetBytes(32));
        CertbotEabHmacKey = Base64Url(RandomNumberGenerator.GetBytes(32));
    }

    public TestTlsPki Tls { get; }

    /// <summary>The single-use EAB HMAC key (base64url) provisioned on the server for <see cref="EabKeyId"/>.</summary>
    public string EabHmacKey { get; }

    /// <summary>
    /// A second single-use EAB HMAC key (base64url) for <see cref="CertbotEabKeyId"/>: EAB keys are consumed on
    /// first binding, so each ACME client in the feature binds its own.
    /// </summary>
    public string CertbotEabHmacKey { get; }

    public IContainer Client { get; private set; } = null!;

    public IContainer? TelemetryCollector { get; private set; }

    public string ClientIp => $"{_prefix}.20";

    public string DirectoryUrl => $"https://{ServerAlias}:{ServerPort}/directory";

    public static async Task<IqAcmeEnvironment> StartAsync(
        CancellationToken cancellationToken = default,
        IqAuthorityConfiguration? authorityConfiguration = null,
        bool disableCaaChecks = false,
        IqRevocationConfiguration? revocationConfiguration = null,
        bool enableHttp = false,
        bool enableTelemetry = false)
    {
        var (serverImage, clientImage) = await IqImages.GetAsync(cancellationToken).ConfigureAwait(false);
        var environment = new IqAcmeEnvironment(TestTlsPki.Create(
            ServerAlias, TosServerAlias, IqRevocationConfiguration.IssuerAlias))
        {
            _serverImage = serverImage,
            _authorityConfiguration = authorityConfiguration,
            _revocationConfiguration = revocationConfiguration,
            _disableCaaChecks = disableCaaChecks,
            _enableHttp = enableHttp,
            _enableTelemetry = enableTelemetry
        };
        try
        {
            await environment.Start(clientImage, cancellationToken).ConfigureAwait(false);
            return environment;
        }
        catch
        {
            await environment.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task Start(IImage clientImage, CancellationToken cancellationToken)
    {
        await CreateNetwork(cancellationToken).ConfigureAwait(false);

        if (_enableTelemetry)
        {
            TelemetryCollector = Track(new ContainerBuilder("otel/opentelemetry-collector-contrib:0.123.0")
                .WithNetwork(_network)
                .WithNetworkAliases("telemetry")
                .WithResourceMapping([], "/tmp/traces.json", fileMode: Unix.FileMode666)
                .WithResourceMapping(Encoding.UTF8.GetBytes("""
                    receivers:
                      otlp:
                        protocols:
                          grpc:
                            endpoint: 0.0.0.0:4317
                    exporters:
                      prometheus:
                        endpoint: 0.0.0.0:8889
                      file:
                        path: /tmp/traces.json
                        flush_interval: 1s
                    extensions:
                      health_check:
                        endpoint: 0.0.0.0:13133
                    service:
                      extensions: [health_check]
                      pipelines:
                        metrics:
                          receivers: [otlp]
                          exporters: [prometheus]
                        traces:
                          receivers: [otlp]
                          exporters: [file]
                    """), "/etc/otelcol-contrib/config.yaml", fileMode: Unix.FileMode644)
                .WithPortBinding(13133, true)
                .WithWaitStrategy(Wait.ForUnixContainer()
                    .UntilHttpRequestIsSucceeded(r => r.ForPort(13133).ForPath("/")))
                .Build());
            await TelemetryCollector.StartAsync(cancellationToken).ConfigureAwait(false);
        }

        _dns = Track(new ContainerBuilder("python:3.12-alpine")
            .WithNetwork(_network)
            .WithNetworkAliases(DnsAlias)
            .WithCreateParameterModifier(p => StaticIp(p, DnsIp))
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(RepositoryPaths.IqProject, "acme", "dns_server.py")),
                "/app/dns_server.py",
                fileMode: Unix.FileMode644)
            .WithEnvironment("IQ_DNS_ZONES", "example.com")
            .WithEnvironment("PYTHONUNBUFFERED", "1")
            .WithCommand("python", "/app/dns_server.py")
            .WithPortBinding(DnsApiPort, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilHttpRequestIsSucceeded(r => r.ForPort(DnsApiPort).ForPath("/health")))
            .Build());
        await _dns.StartAsync(cancellationToken).ConfigureAwait(false);

        if (_revocationConfiguration is not null)
        {
            _issuer = Track(_revocationConfiguration.BuildIssuer(_network, Tls));
            await _issuer.StartAsync(cancellationToken).ConfigureAwait(false);
        }

        _server = Track(BuildServer(ServerAlias, $"{_prefix}.10", configure: null));
        Client = Track(new ContainerBuilder(clientImage)
            .WithNetwork(_network)
            .WithNetworkAliases(ClientAlias)
            .WithCreateParameterModifier(p =>
            {
                StaticIp(p, ClientIp);
                p.HostConfig ??= new HostConfig();
                p.HostConfig.DNS = [DnsIp];
            })
            .WithResourceMapping(
                Encoding.ASCII.GetBytes(Tls.RootPem),
                "/usr/local/share/ca-certificates/iq-tls-root.crt",
                fileMode: Unix.FileMode644)
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(RepositoryPaths.IqProject, "client", "scripts", "acme-raw.sh")),
                "/usr/local/bin/acme-raw.sh",
                fileMode: Unix.FileMode755)
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(RepositoryPaths.IqProject, "client", "scripts", "dns_iq.sh")),
                "/root/.acme.sh/dnsapi/dns_iq.sh",
                fileMode: Unix.FileMode755)
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(RepositoryPaths.IqProject, "client", "scripts", "certbot-dns-iq.sh")),
                "/usr/local/bin/certbot-dns-iq.sh",
                fileMode: Unix.FileMode755)
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(RepositoryPaths.IqProject, "client", "scripts", "est-crypto.py")),
                "/usr/local/bin/est-crypto.py",
                fileMode: Unix.FileMode644)
            .WithResourceMapping(
                File.ReadAllBytes(Path.Combine(RepositoryPaths.IqProject, "client", "scripts", "device-attest.py")),
                "/usr/local/bin/device-attest.py",
                fileMode: Unix.FileMode644)
            .WithEnvironment("ACME_DIRECTORY", DirectoryUrl)
            .WithEnvironment("IQ_DNS_API", $"http://{DnsAlias}:{DnsApiPort}")
            .WithEntrypoint("sleep", "infinity")
            .Build());
        await Task.WhenAll(_server.StartAsync(cancellationToken), Client.StartAsync(cancellationToken))
            .ConfigureAwait(false);

        var trust = await Client.ExecAsync(["update-ca-certificates"], cancellationToken).ConfigureAwait(false);
        if (trust.ExitCode != 0)
        {
            throw new InvalidOperationException($"update-ca-certificates failed: {trust.Stderr}");
        }

        // The http-01 scenarios answer challenges from the client container (acme.sh / certbot --standalone).
        await AddDnsRecord("acme.example.com", "A", ClientIp, cancellationToken).ConfigureAwait(false);
        await AddDnsRecord("certbot.example.com", "A", ClientIp, cancellationToken).ConfigureAwait(false);
    }

    private string DnsIp => $"{_prefix}.53";

    /// <summary>
    /// Starts a second server (alias <see cref="TosServerAlias"/>) whose terms of service require agreement
    /// and were last updated at <paramref name="tosLastUpdate"/>. The caller owns the returned container.
    /// </summary>
    public async Task<IContainer> StartTosServerAsync(DateTimeOffset tosLastUpdate, CancellationToken cancellationToken)
    {
        var container = BuildServer(TosServerAlias, $"{_prefix}.11", b => b
            .WithEnvironment("AcmeServer__TOS__RequireAgreement", "true")
            .WithEnvironment("AcmeServer__TOS__Url", $"https://{TosServerAlias}:{ServerPort}/terms-of-service")
            .WithEnvironment("AcmeServer__TOS__LastUpdate", tosLastUpdate.UtcDateTime.ToString("O")));
        await container.StartAsync(cancellationToken).ConfigureAwait(false);
        return container;
    }

    /// <summary>
    /// Starts a scenario-owned server with an explicit manufacturer root, using the second server's
    /// TLS alias. Only the public root is copied; the software AIK private key stays in the client.
    /// </summary>
    public async Task<IContainer> StartAttestationServerAsync(
        string rootPem, CancellationToken cancellationToken = default)
    {
        var container = BuildServer(TosServerAlias, $"{_prefix}.11", b => b
            .WithResourceMapping(Encoding.ASCII.GetBytes(rootPem), "/certs/manufacturer.pem",
                fileMode: Unix.FileMode644)
            .WithEnvironment("Attestation__TrustAnchors__0", "/certs/manufacturer.pem"));
        try
        {
            await container.StartAsync(cancellationToken).ConfigureAwait(false);
            return container;
        }
        catch
        {
            await container.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Runs a bash script in the client container.</summary>
    public Task<ExecResult> ExecClientAsync(string script, CancellationToken cancellationToken = default) =>
        Client.ExecAsync(["bash", "-c", script], cancellationToken);

    /// <summary>Publishes a record on the test DNS server through its mapped control API.</summary>
    public async Task AddDnsRecord(string name, string type, string value, CancellationToken cancellationToken = default)
    {
        using var http = new HttpClient();
        var uri = new UriBuilder("http", _dns.Hostname, _dns.GetMappedPublicPort(DnsApiPort), "/records").Uri;
        // A buffered body: the stdlib control API reads Content-Length and does not decode chunked requests.
        using var content = new StringContent(
            JsonSerializer.Serialize(new { name, type, value }),
            Encoding.UTF8,
            "application/json");
        using var response = await http.PostAsync(uri, content, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>Collects server and DNS logs to explain a failing scenario.</summary>
    public async Task<string> GetDiagnosticsAsync(params IContainer?[] extra)
    {
        var builder = new StringBuilder();
        foreach (var container in new[] { _server, _dns, _issuer, TelemetryCollector }.Concat(extra).OfType<IContainer>())
        {
            try
            {
                var (stdout, stderr) = await container.GetLogsAsync().ConfigureAwait(false);
                builder.AppendLine($"===== {container.Name} =====").AppendLine(Tail(stdout)).AppendLine(Tail(stderr));
            }
            catch (Exception e)
            {
                builder.AppendLine($"===== {container.Name}: logs unavailable ({e.Message}) =====");
            }
        }

        return builder.ToString();

        static string Tail(string text) => text.Length <= 20_000 ? text : text[^20_000..];
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var container in Enumerable.Reverse(_containers))
        {
            await container.DisposeAsync().ConfigureAwait(false);
        }

        if (_network != null)
        {
            await _network.DisposeAsync().ConfigureAwait(false);
        }

        Tls.Dispose();
    }

    private IContainer BuildServer(
        string alias,
        string ip,
        Func<ContainerBuilder, ContainerBuilder>? configure)
    {
        var builder = new ContainerBuilder(_serverImage)
            .WithNetwork(_network)
            .WithNetworkAliases(alias)
            .WithCreateParameterModifier(p =>
            {
                StaticIp(p, ip);
                p.HostConfig ??= new HostConfig();
                p.HostConfig.DNS = [DnsIp];
            })
            .WithResourceMapping(Encoding.ASCII.GetBytes(Tls.LeafPem), "/certs/tls.crt", fileMode: Unix.FileMode644)
            .WithResourceMapping(Encoding.ASCII.GetBytes(Tls.LeafKeyPem), "/certs/tls.key", fileMode: Unix.FileMode644)
            .WithEnvironment("Kestrel__Certificates__Default__Path", "/certs/tls.crt")
            .WithEnvironment("Kestrel__Certificates__Default__KeyPath", "/certs/tls.key")
            .WithEnvironment("AllowedHosts", $"localhost;127.0.0.1;[::1];{ServerAlias};{TosServerAlias}")
            // Resolve through the container's resolver (Docker DNS -> the test DNS server), not public DoH.
            .WithEnvironment("AcmeServer__DnsEndpoint", "System")
            .WithEnvironment("AcmeServer__DisableCaaChecks", _disableCaaChecks ? "true" : "false")
            .WithEnvironment($"AcmeServer__ExternalAccountKey__{EabKeyId}__MacKey", EabHmacKey)
            .WithEnvironment($"AcmeServer__ExternalAccountKey__{EabKeyId}__MacAlgorithm", "HS256")
            .WithEnvironment($"AcmeServer__ExternalAccountKey__{CertbotEabKeyId}__MacKey", CertbotEabHmacKey)
            .WithEnvironment($"AcmeServer__ExternalAccountKey__{CertbotEabKeyId}__MacAlgorithm", "HS256")
            .WithCommand(_authorityConfiguration?.ServerArguments ??
            [
                "--authority", "https://iq.test",
                "--audience", "https://iq.test",
                "--dn", "CN=OpenCertServer IQ CA",
                "--port", ServerPort.ToString(System.Globalization.CultureInfo.InvariantCulture)
            ])
            .WithPortBinding(ServerPort, true)
            .WithWaitStrategy(Wait.ForUnixContainer()
                .UntilHttpRequestIsSucceeded(r => r
                    .ForPort(ServerPort)
                    .ForPath("/health")
                    .UsingTls()
                    .UsingHttpMessageHandler(Tls.CreateTrustingHandler())));
        if (_enableHttp)
        {
            builder = builder
                .WithEnvironment("Kestrel__Endpoints__Http__Url", $"http://*:{HttpPort}")
                .WithEnvironment("Kestrel__Endpoints__Https__Url", $"https://*:{ServerPort}");
        }

        if (_enableTelemetry)
        {
            builder = builder
                .WithEnvironment("Telemetry__Enabled", "true")
                .WithEnvironment("Telemetry__OtlpEndpoint", "http://telemetry:4317")
                .WithEnvironment("Telemetry__ServiceName", "opencertserver-iq")
                .WithEnvironment("OTEL_METRIC_EXPORT_INTERVAL", "1000")
                .WithEnvironment("OTEL_BSP_SCHEDULE_DELAY", "200")
                .WithEnvironment("OTEL_TRACES_SAMPLER", "always_on");
        }

        if (!_disableCaaChecks)
        {
            builder = builder.WithEnvironment("AcmeServer__CAAIdentities__0", CaaIdentity);
        }

        builder = _authorityConfiguration?.Configure(builder) ?? builder;
        builder = _revocationConfiguration?.Configure(builder, Tls) ?? builder;
        return (configure?.Invoke(builder) ?? builder).Build();
    }

    private async Task CreateNetwork(CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            _prefix = $"198.{18 + Random.Shared.Next(2)}.{Random.Shared.Next(256)}";
            var network = new NetworkBuilder()
                .WithName($"oc-iq-{Guid.NewGuid():N}")
                .WithCreateParameterModifier(p => p.IPAM = new IPAM
                {
                    Config = [new IPAMConfig { Subnet = $"{_prefix}.0/24", IPRange = $"{_prefix}.128/25" }]
                })
                .Build();
            try
            {
                await network.CreateAsync(cancellationToken).ConfigureAwait(false);
                _network = network;
                return;
            }
            catch (Exception) when (attempt < 5)
            {
                // Most likely the random subnet overlaps a concurrently running harness; pick another.
                await network.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private void StaticIp(CreateContainerParameters parameters, string ip)
    {
        parameters.NetworkingConfig ??= new NetworkingConfig();
        parameters.NetworkingConfig.EndpointsConfig ??= new Dictionary<string, EndpointSettings>();
        if (!parameters.NetworkingConfig.EndpointsConfig.TryGetValue(_network.Name, out var endpoint))
        {
            endpoint = new EndpointSettings();
            parameters.NetworkingConfig.EndpointsConfig[_network.Name] = endpoint;
        }

        endpoint.IPAMConfig = new EndpointIPAMConfig { IPv4Address = ip };
    }

    private IContainer Track(IContainer container)
    {
        _containers.Add(container);
        return container;
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
