namespace OpenCertServer.Iq.Tests.Support;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.IO;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Configurations;
using DotNet.Testcontainers.Containers;
using DotNet.Testcontainers.Networks;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Testing;

/// <summary>
/// The black-box topology for the chiseled appliance IQ scenarios. One appliance container (a
/// <c>Unified</c>, <c>Ca</c>, or <c>Ra</c> role image built by <see cref="IqImages.GetApplianceImageAsync"/>)
/// is reached over the network from the Ubuntu <c>client</c> container, which runs <c>curl</c> and
/// <c>openssl</c>. Unlike <see cref="IqAcmeEnvironment"/>, a hardened appliance is TLS-1.3-only and
/// HTTPS-only, so the scenarios assert the hardened posture directly: a TLS-1.3 handshake, rejection of
/// TLS 1.0/1.1/1.2, an unprivileged process, a health probe, and the role's own endpoint surface.
/// </summary>
/// <remarks>
/// A hardened appliance permits no non-HTTPS listener, so the HTTP-to-HTTPS redirect that the main image
/// offers does not apply here; instead the HTTPS-only invariant is proven by showing the appliance refuses
/// to start when a Kestrel HTTP endpoint is configured.
/// </remarks>
internal sealed class IqApplianceEnvironment : IAsyncDisposable
{
    public const int ServerPort = 6001;
    public const string ServerAlias = "appliance";
    public const string ClientAlias = "client";
    public const string DataDirectory = "/var/lib/opencertserver";

    private readonly List<IContainer> _containers = [];
    private INetwork _network = null!;
    private IContainer _server = null!;
    private string _containerName = null!;
    private string _applianceImageName = null!;
    private RelationalTestDatabase? _database;

    private IqApplianceEnvironment(TestTlsPki tls)
    {
        Tls = tls;
        Certificates = BuildCertificates();
    }

    public TestTlsPki Tls { get; }

    /// <summary>The role-under-test, one of Unified, Ca, or Ra.</summary>
    public string Role { get; private set; } = "Unified";

    /// <summary>
    /// The relational engine the appliance targets: <c>postgres</c>, <c>mssql</c>, or empty for the
    /// default in-container store. Empty selects the base per-role image; a concrete engine selects the
    /// matching engine-variant image (see <see cref="StartWithDatabaseAsync"/>).
    /// </summary>
    public string Engine { get; private set; } = string.Empty;

    /// <summary>
    /// The relational database the appliance writes to (null when the environment is booted without a
    /// database). The appliance is handed its connection string as <c>ConnectionStrings:OpenCertServer</c>
    /// and the schema is applied out-of-band by the test before the appliance starts.
    /// </summary>
    public RelationalTestDatabase? Database { get; private set; }

    /// <summary>Whether the appliance was booted to trip the HTTPS-only startup guard (expected to fail).</summary>
    public bool HttpGuard { get; private set; }

    public string HttpGuardReason { get; private set; } = string.Empty;
    private readonly MemoryStream _guardStdout = new();
    private readonly MemoryStream _guardStderr = new();

    /// <summary>The non-root user the chiseled base runs the appliance as (chiseled "app").</summary>
    public string ExpectedUser { get; } = "1654";

    public IContainer Server { get; private set; } = null!;
    public IContainer Client { get; private set; } = null!;
    public string ApplianceImageName => _applianceImageName;

    /// <summary>The PEM material a booted appliance needs: a TLS leaf, a CA profile cert, and RA materials.</summary>
    public sealed record CertificateMaterials(
        string RsaPem,
        string RsaKeyPem,
        string EcdsaPem,
        string EcdsaKeyPem,
        string ClientCertPem,
        string ClientKeyPem,
        string CaTrustRootPem);

    public CertificateMaterials Certificates { get; }

    public static async Task<IqApplianceEnvironment> StartAsync(
        string role,
        CancellationToken cancellationToken = default,
        bool httpGuard = false)
    {
        var roleLower = role.Trim();
        var environment = new IqApplianceEnvironment(TestTlsPki.Create(ServerAlias, ClientAlias))
        {
            Role = roleLower,
            HttpGuard = httpGuard,
            _containerName = $"oc-appliance-{roleLower.ToLowerInvariant()}-{Guid.NewGuid():N}"
        };
        try
        {
            await environment.BootAsync(cancellationToken).ConfigureAwait(false);
            return environment;
        }
        catch
        {
            await environment.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static string NormalizeEngine(string? engine) =>
        string.IsNullOrWhiteSpace(engine)
            ? ""
            : engine.Trim().ToLowerInvariant() switch
            {
                "mssql" or "sqlserver" => "mssql",
                _ => "postgres"
            };

    /// <summary>
    /// Boots the appliance against a Testcontainers relational database: the database is created first
    /// and its schema migrated out-of-band, then the appliance is started with
    /// <c>ConnectionStrings:OpenCertServer</c> pointed at it. Used by the relational-storage scenarios.
    /// </summary>
    public static async Task<IqApplianceEnvironment> StartWithDatabaseAsync(
        string role,
        string engine,
        CancellationToken cancellationToken = default)
    {
        var roleLower = role.Trim();
        var engineTag = NormalizeEngine(engine);
        var environment = new IqApplianceEnvironment(TestTlsPki.Create(ServerAlias, ClientAlias))
        {
            Role = roleLower,
            Engine = engineTag,
            _containerName = $"oc-appliance-{roleLower.ToLowerInvariant()}-{Guid.NewGuid():N}"
        };
        try
        {
            await environment.BootWithDatabaseAsync(cancellationToken).ConfigureAwait(false);
            return environment;
        }
        catch
        {
            await environment.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task BootAsync(CancellationToken cancellationToken, RelationalTestDatabase? database = null)
    {
        _network = await CreateNetwork(cancellationToken).ConfigureAwait(false);
        _database = database;
        if (database is not null)
        {
            // The schema is applied out-of-band, before the appliance starts: the test starts the database
            // on the shared network and migrates it, so the appliance only connects to a ready database.
            await database.StartAsync(_network, cancellationToken).ConfigureAwait(false);
            Database = database;
            if (Role is "Unified" or "Ca")
            {
                using var rsaProfile = CreateProfile("rsa", Certificates.RsaPem, Certificates.RsaKeyPem);
                using var ecdsaProfile = CreateProfile("ecdsa", Certificates.EcdsaPem, Certificates.EcdsaKeyPem);
                await database.SeedProfilesAsync(database.ConnectionString, "rsa",
                    [rsaProfile, ecdsaProfile], cancellationToken).ConfigureAwait(false);
            }
        }

        var (applianceImage, applianceImageName) =
            await IqImages.GetApplianceImageAsync(Role, cancellationToken, Engine).ConfigureAwait(false);
        _applianceImageName = applianceImageName;
        var clientImage = await IqImages.GetClientAsync(cancellationToken).ConfigureAwait(false);

        var builder = new ContainerBuilder(applianceImage)
            .WithNetwork(_network)
            .WithName(_containerName)
            .WithNetworkAliases(ServerAlias)
            .WithResourceMapping(Encoding.ASCII.GetBytes(Tls.LeafPem), FilePath.Of("/certs/tls.crt"),
                fileMode: Unix.FileMode644)
            .WithResourceMapping(Encoding.ASCII.GetBytes(Tls.LeafKeyPem), FilePath.Of("/certs/tls.key"),
                fileMode: Unix.FileMode644)
            .WithEnvironment("Kestrel__Certificates__Default__Path", "/certs/tls.crt")
            .WithEnvironment("Kestrel__Certificates__Default__KeyPath", "/certs/tls.key")
            .WithEnvironment("AllowedHosts", "localhost;127.0.0.1;[::1];" + ServerAlias)
            .WithEnvironment("port", ServerPort.ToString(System.Globalization.CultureInfo.InvariantCulture))
            .WithEnvironment("Appliance__Hardened", "true")
            .WithEnvironment("Appliance__Role", Role)
            .WithEnvironment("Telemetry__Enabled", "false")
            .WithEnvironment("Jwt__Authority", "https://iq.test")
            .WithEnvironment("Jwt__Audiences__0", "https://iq.test")
            .WithPortBinding(ServerPort, true);

        // The relational backend (postgres/mssql) is selected by the engine-baked image and reached via a
        // runtime-supplied connection string, the same way a deployment supplies a database password. The
        // engine variant image bakes Appliance__Engine and the relational persistence selectors; the test
        // supplies the connection string pointing at the "db" network alias.
        if (database is not null)
        {
            builder = builder
                .WithEnvironment("ConnectionStrings__OpenCertServer", database.NetworkConnectionString);
            if (Engine == "mssql")
            {
                // The MSSQL provider trusts the server certificate on the test network; a deployment would
                // pin a real CA. Documented here so the appliance can open the test connection.
                builder = builder.WithEnvironment("ConnectionStrings__OpenCertServer",
                    AppendTrustedCertificate(database.NetworkConnectionString));
            }
        }

        // The CA and Unified roles issue from a persistent store; RA does not (its DataDirectory is
        // skipped), so only mount one where the role needs it. A tmpfs mount (in-container memory) is
        // always writable by the unprivileged process and sidesteps the host-uid-mapping quirk that
        // makes a bind-mounted data directory unwritable on macOS Docker Desktop. A hardened Unified
        // appliance requires CAA checks on, EAB, and both ACME workers; a hardened CA runs the
        // responder with SCEP off so its surface is CA-only.
        if (Role is "Unified" or "Ca")
        {
            builder = builder
                .WithTmpfsMount(DataDirectory, AccessMode.ReadWrite)
                .WithResourceMapping(Encoding.ASCII.GetBytes(Certificates.RsaPem), FilePath.Of("/certs/rsa.pem"),
                    fileMode: Unix.FileMode644)
                .WithResourceMapping(Encoding.ASCII.GetBytes(Certificates.RsaKeyPem), FilePath.Of("/certs/rsa.key"),
                    fileMode: Unix.FileMode644)
                .WithResourceMapping(Encoding.ASCII.GetBytes(Certificates.EcdsaPem), FilePath.Of("/certs/ecdsa.pem"),
                    fileMode: Unix.FileMode644)
                .WithResourceMapping(Encoding.ASCII.GetBytes(Certificates.EcdsaKeyPem), FilePath.Of("/certs/ecdsa.key"),
                    fileMode: Unix.FileMode644)
                .WithEnvironment("rsa__Pem", "/certs/rsa.pem")
                .WithEnvironment("rsa__KeyPem", "/certs/rsa.key")
                .WithEnvironment("ecdsa__Pem", "/certs/ecdsa.pem")
                .WithEnvironment("ecdsa__KeyPem", "/certs/ecdsa.key")
                .WithEnvironment("Appliance__DataDirectory", DataDirectory);
            if (Role is "Unified")
            {
                builder = builder
                    .WithEnvironment("AcmeServer__DisableCaaChecks", "false")
                    .WithEnvironment("AcmeServer__ExternalAccountRequired", "true")
                    .WithEnvironment("AcmeServer__HostedWorkers__EnableValidationService", "true")
                    .WithEnvironment("AcmeServer__HostedWorkers__EnableIssuanceService", "true");
            }
            else
            {
                builder = builder.WithEnvironment("Scep__Enabled", "false");
            }
        }
        else // Ra: a thin peer client; a valid-but-unreachable HTTPS peer is enough to boot standalone.
        {
            builder = builder
                .WithEnvironment("Ra__PeerUrl", "https://ca.example.com:5001")
                .WithEnvironment("Ra__Scope", "ra.example.com")
                .WithResourceMapping(Encoding.ASCII.GetBytes(Certificates.ClientCertPem),
                    FilePath.Of("/certs/ra-client.crt"),
                    fileMode: Unix.FileMode644)
                .WithResourceMapping(Encoding.ASCII.GetBytes(Certificates.ClientKeyPem),
                    FilePath.Of("/certs/ra-client.key"),
                    fileMode: Unix.FileMode644)
                .WithResourceMapping(Encoding.ASCII.GetBytes(Certificates.CaTrustRootPem),
                    FilePath.Of("/certs/ra-trust.pem"),
                    fileMode: Unix.FileMode644)
                .WithEnvironment("Ra__ClientCertificatePath", "/certs/ra-client.crt")
                .WithEnvironment("Ra__ClientPrivateKeyPath", "/certs/ra-client.key")
                .WithEnvironment("Ra__CaTrustRoots__0", "/certs/ra-trust.pem");
        }

        // The HTTPS-only guard: a hardened appliance refuses a non-HTTPS Kestrel endpoint at startup.
        if (HttpGuard)
        {
            // A hardened appliance refuses a non-HTTPS Kestrel endpoint at startup. The rejection is an
            // unhandled exception in the appliance Main, written to the container's stderr; capture the
            // stream live with an output consumer because a post-hoc GetLogs on an exited container is
            // unreliable, and there is no health probe to wait on.
            builder = builder
                .WithOutputConsumer(new GuardConsumer(_guardStdout, _guardStderr))
                .WithEnvironment("Kestrel__Endpoints__Http__Url", "http://*:6000")
                .WithEnvironment("Kestrel__Endpoints__Https__Url", $"https://*:{ServerPort}");
        }
        else
        {
            // A hardened appliance is TLS-1.3-only, so the host-side HTTP/TLS wait the ACME feature uses
            // is unreliable here; instead wait for the deterministic Kestrel "listening" log line. Every
            // protocol and endpoint assertion then runs through the client container (the black-box side),
            // which trusts the test root and speaks the server's HTTPS endpoint over the network.
            builder = builder.WithWaitStrategy(Wait.ForUnixContainer()
                .UntilMessageIsLogged("Now listening on"));
        }

        _server = Track(builder.Build());
        Client = Track(new ContainerBuilder(clientImage)
            .WithNetwork(_network)
            .WithNetworkAliases(ClientAlias)
            .WithResourceMapping(Encoding.ASCII.GetBytes(Tls.RootPem),
                FilePath.Of("/usr/local/share/ca-certificates/iq-appliance-root.crt"), fileMode: Unix.FileMode644)
            .WithEntrypoint("sleep", "infinity")
            .Build());

        if (HttpGuard)
        {
            // The guard trips before a listener is open, so there is no health probe to wait on. The
            // rejection is an unhandled exception in the appliance Main (before Kestrel starts); capture
            // it live via the output consumer and poll for the container to leave the Running state, since
            // a no-wait container is reported ready immediately.
            await _server.StartAsync(cancellationToken).ConfigureAwait(false);
            for (int i = 0; i < 50; i++)
            {
                if (_server.State != TestcontainersStates.Running)
                {
                    break;
                }

                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
            }

            var (gstdout, gstderr) = await _server.GetLogsAsync().ConfigureAwait(false);
            HttpGuardReason =
                System.Text.Encoding.UTF8.GetString(_guardStdout.ToArray()) +
                System.Text.Encoding.UTF8.GetString(_guardStderr.ToArray()) +
                gstdout + gstderr;
            return;
        }

        await _server.StartAsync(cancellationToken).ConfigureAwait(false);
        await Client.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Boots the appliance against a freshly created, out-of-band-migrated relational database.</summary>
    private async Task BootWithDatabaseAsync(CancellationToken cancellationToken)
    {
        var database = new RelationalTestDatabase(Engine == "mssql" ? "MSSQL" : "PostgreSQL");
        await BootAsync(cancellationToken, database).ConfigureAwait(false);
    }

    /// <summary>Appends TrustServerCertificate=true so the appliance can open the test network's connection.</summary>
    private static string AppendTrustedCertificate(string connectionString) =>
        connectionString.Contains("TrustServerCertificate", StringComparison.OrdinalIgnoreCase)
            ? connectionString
            : connectionString.TrimEnd(';') + ";TrustServerCertificate=true";

    /// <summary>Runs a bash script in the client container.</summary>
    public Task<ExecResult> ExecClientAsync(string script, CancellationToken cancellationToken = default) =>
        Client.ExecAsync(["bash", "-c", script], cancellationToken);

    /// <summary>Waits for the client to reach the appliance over the given TLS version, capturing s_client output.</summary>
    public Task<ExecResult> ClientTlsHandshakeAsync(
        string tlsFlag,
        bool legacy,
        CancellationToken cancellationToken = default)
    {
        var ciphers = legacy ? " -cipher 'ALL:@SECLEVEL=0'" : "";
        var script =
            $"mkdir -p /work && timeout 25s openssl s_client {tlsFlag}{ciphers}"
          + $" -connect '{ServerAlias}:{ServerPort}' -servername '{ServerAlias}'"
          + $" -CAfile /usr/local/share/ca-certificates/iq-appliance-root.crt < /dev/null 2>&1";
        return ExecClientAsync(script, cancellationToken);
    }

    /// <summary>GETs <paramref name="path"/> from the appliance with curl, writing the status/headers/body to /work.</summary>
    public async Task<ExecResult> ClientGetAsync(string path, CancellationToken cancellationToken = default)
    {
        var script =
            $"mkdir -p /work && curl -sS -D /work/headers -o /work/body -w '%{{http_code}}' "
          + $"--cacert /usr/local/share/ca-certificates/iq-appliance-root.crt "
          + $"'https://{ServerAlias}:{ServerPort}{path}' > /work/status";
        return await ExecClientAsync(script, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Performs a non-GET <paramref name="method"/> against the appliance with curl, writing the status to /work.</summary>
    public async Task<ExecResult> ClientRequestAsync(
        string method,
        string path,
        CancellationToken cancellationToken = default)
    {
        var script =
            $"mkdir -p /work && curl -sS -X {method} -o /dev/null -w '%{{http_code}}' "
          + $"--cacert /usr/local/share/ca-certificates/iq-appliance-root.crt "
          + $"'https://{ServerAlias}:{ServerPort}{path}' > /work/status";
        return await ExecClientAsync(script, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads the status/headers/body a probe wrote to /work inside the client container.</summary>
    public async Task<(int Status, string Headers, string Body)> ReadProbeAsync(
        CancellationToken cancellationToken = default)
    {
        var status = await ExecClientAsync("cat /work/status", cancellationToken).ConfigureAwait(false);
        var headers = await ExecClientAsync("cat /work/headers 2>/dev/null || echo", cancellationToken)
            .ConfigureAwait(false);
        var body = await ExecClientAsync("cat /work/body 2>/dev/null || echo", cancellationToken).ConfigureAwait(false);
        return (int.Parse(status.Stdout.Trim(), System.Globalization.CultureInfo.InvariantCulture),
                headers.Stdout, body.Stdout);
    }

    /// <summary>
    /// Reads the user a *running* container reports, via the Docker Engine API. This is the authoritative
    /// runtime proof that the appliance process is unprivileged: it inspects the container the same way
    /// Testcontainers inspects every other container, and it works under the MTP/Docker-Desktop test host
    /// where the external <c>docker</c> CLI's <c>inspect</c> returns an empty user with exit 0.
    /// </summary>
    public async Task<string> ContainerUserAsync(CancellationToken cancellationToken = default)
    {
        var inspected = await DockerInspection.InspectContainerAsync(_containerName, cancellationToken)
            .ConfigureAwait(false);
        return string.IsNullOrEmpty(inspected) ? "0" : inspected; // A blank means the runtime default, i.e. root.
    }

    /// <summary>
    /// Reads the user baked into the appliance image's config, proving the chiseled base is built to run
    /// unprivileged by default. Uses the Docker Engine API for the same MTP-robustness reason as
    /// <see cref="ContainerUserAsync"/>.
    /// </summary>
    public async Task<string> ImageUserAsync(CancellationToken cancellationToken = default)
    {
        var inspected = await DockerInspection.InspectImageAsync(_applianceImageName, cancellationToken)
            .ConfigureAwait(false);
        return string.IsNullOrEmpty(inspected) ? "0" : inspected; // A blank means the runtime default, i.e. root.
    }

    /// <summary>
    /// A private bridge on a random /24 in RFC 2544 space, shared by the appliance and the client so the
    /// client reaches the appliance by its <see cref="ServerAlias"/>. The appliance is reached over TLS by
    /// name, so it needs a resolvable alias, not just a published host port.
    /// </summary>
    private async Task<INetwork> CreateNetwork(CancellationToken cancellationToken)
    {
        // The client reaches the appliance by the "appliance" network alias (not by a fixed IP), so the
        // subnet can be auto-assigned; a fixed subnet is only needed when the peer address is asserted,
        // and it would collide with IqAcmeEnvironment's pool in a combined run.
        var network = new NetworkBuilder()
            .WithName($"oc-appliance-{Guid.NewGuid():N}")
            .Build();
        try
        {
            await network.CreateAsync(cancellationToken).ConfigureAwait(false);
            return network;
        }
        catch (Exception)
        {
            await network.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task<string> ServerLogsAsync(CancellationToken cancellationToken = default)
    {
        var logs = HttpGuard ? HttpGuardReason : string.Empty;
        try
        {
            var (stdout, stderr) = await _server.GetLogsAsync().ConfigureAwait(false);
            logs += stdout + stderr;
        }
        catch
        {
            if (string.IsNullOrWhiteSpace(logs))
            {
                logs = "server logs unavailable";
            }
        }

        return logs;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var container in Enumerable.Reverse(_containers))
        {
            try
            {
                await container.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
                // Best-effort teardown: a tripped guard may never have produced a live container.
            }
        }

        await _network.DisposeAsync().ConfigureAwait(false);
        Tls.Dispose();
    }

    private static CertificateMaterials BuildCertificates()
    {
        var rsa = SelfSigned("OpenCertServer IQ RSA Profile", Ecdsa: false);
        var ecdsa = SelfSigned("OpenCertServer IQ ECDSA Profile", Ecdsa: true);
        return new CertificateMaterials(
            rsa.CertPem, rsa.KeyPem,
            ecdsa.CertPem, ecdsa.KeyPem,
            ecdsa.CertPem, ecdsa.KeyPem,
            ecdsa.CertPem);
    }

    private static CaProfile CreateProfile(string name, string certificatePem, string keyPem)
    {
        using var certificateWithKey = X509Certificate2.CreateFromPem(certificatePem, keyPem);
        AsymmetricAlgorithm privateKey = name == "rsa"
            ? certificateWithKey.GetRSAPrivateKey()!
            : certificateWithKey.GetECDsaPrivateKey()!;
        return new CaProfile
        {
            Name = name,
            PrivateKey = privateKey,
            CertificateChain = [X509Certificate2.CreateFromPem(certificatePem)],
            PublishedCertificateChain = [X509Certificate2.CreateFromPem(certificatePem)],
            CertificateValidity = TimeSpan.FromDays(90)
        };
    }

    private static (string CertPem, string KeyPem) SelfSigned(string subject, bool Ecdsa)
    {
        // The --profile rsa path calls GetRSAPrivateKey() on the configured cert, so the RSA material must
        // actually be an RSA key; the ECDSA material (used for the ecdsa profile, the TLS leaf, and the RA
        // client) stays ECDSA.
        var now = DateTimeOffset.UtcNow;
        if (Ecdsa)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest(new X500DistinguishedName($"CN={subject}"),
                key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            using var certificate = request.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(30));
            return (certificate.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem());
        }

        using var rsa = RSA.Create(2048);
        var rsaRequest = new CertificateRequest(new X500DistinguishedName($"CN={subject}"), rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rsaRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rsaRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var rsaCertificate = rsaRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(30));
        return (rsaCertificate.ExportCertificatePem(), rsa.ExportPkcs8PrivateKeyPem());
    }

    private IContainer Track(IContainer container)
    {
        _containers.Add(container);
        return container;
    }
}

/// <summary>
/// A live output consumer that captures a container's stdout/stderr into in-memory streams. Used by the
/// HTTPS-only guard, whose rejection is an unhandled exception in the appliance's startup path and so must
/// be captured as the process runs rather than read back after the container has exited.
/// </summary>
internal sealed class GuardConsumer : IOutputConsumer
{
    private readonly MemoryStream _stdout;
    private readonly MemoryStream _stderr;

    public GuardConsumer(Stream stdout, Stream stderr)
    {
        _stdout = (MemoryStream)stdout;
        _stderr = (MemoryStream)stderr;
    }

    public bool Enabled { get; } = true;
    public Stream Stdout => _stdout;
    public Stream Stderr => _stderr;

    // Testcontainers may dispose the consumer after the container exits; the owning environment still needs
    // to read the captured bytes, so the streams are intentionally left for the environment/GC to release.
    public void Dispose()
    {
    }
}
