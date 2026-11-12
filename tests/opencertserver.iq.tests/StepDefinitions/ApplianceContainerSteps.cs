namespace OpenCertServer.Iq.Tests.StepDefinitions;

using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>
/// Boots one chiseled appliance image per role (from the Linux client container over the network) and
/// asserts the hardened, role-appropriate posture: an unprivileged process, TLS 1.3 only, no
/// <c>Server</c> header, a healthy endpoint, and the endpoints the role serves versus the ones it hides.
/// A final scenario proves the HTTPS-only startup guard a hardened appliance enforces.
/// </summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class ApplianceContainerSteps
{
    public const string FeatureTitle =
        "Chiseled appliance containers are hardened and serve their role";

    private const string TrustRoot = "/usr/local/share/ca-certificates/iq-appliance-root.crt";

    private readonly ScenarioContext _scenarioContext;
    private IqApplianceEnvironment? _environment;

    public ApplianceContainerSteps(ScenarioContext scenarioContext)
    {
        _scenarioContext = scenarioContext;
    }

    [Given(@"^the ""(.*)"" appliance is deployed as a chiseled Ubuntu 24.04 image$")]
    public async Task DeployRole(string role)
    {
        _environment = await IqApplianceEnvironment.StartAsync(role)
            .ConfigureAwait(false);
        _scenarioContext.Set(_environment);
    }

    [Given("^a hardened appliance is started with a plain-HTTP Kestrel endpoint$")]
    public async Task StartHttpGuard()
    {
        _environment = await IqApplianceEnvironment.StartAsync("Unified", httpGuard: true)
            .ConfigureAwait(false);
        _scenarioContext.Set(_environment);
    }

    [Then(@"^the image and the running process run as the unprivileged user ""(.*)""$")]
    public async Task AssertUnprivilegedUser(string user)
    {
        var imageUser = await _environment!.ImageUserAsync().ConfigureAwait(false);
        var containerUser = await _environment.ContainerUserAsync().ConfigureAwait(false);
        Assert.Equal(user, imageUser);
        Assert.Equal(user, containerUser);
    }

    [Then(@"^a ""(TLS 1\.[23])"" handshake completes$")]
    public async Task AssertTlsHandshake(string protocol)
    {
        var option = protocol == "TLS 1.3" ? "-tls1_3" : "-tls1_2";
        var result = await _environment!.ClientTlsHandshakeAsync(option, legacy: false)
            .ConfigureAwait(false);
        Assert.True(result.ExitCode == 0, $"TLS handshake failed:\n{result.Stdout}");
        var version = protocol == "TLS 1.3" ? "TLSv1.3" : "TLSv1.2";
        Assert.Contains($"New, {version}", result.Stdout, StringComparison.Ordinal);
    }

    [Then(@"^a ""(TLS 1\.[23])"" handshake is rejected$")]
    public async Task AssertTlsRejected(string protocol)
    {
        var option = protocol == "TLS 1.2" ? "-tls1_2" : "-tls1_3";
        var result = await _environment!.ClientTlsHandshakeAsync(option, legacy: true)
            .ConfigureAwait(false);
        Assert.NotEqual(0, result.ExitCode);
        // A legacy version is refused at the protocol level, never a successful cipher negotiation.
        Assert.DoesNotContain("-----BEGIN CERTIFICATE-----", result.Stdout, StringComparison.Ordinal);
    }

    [Then(@"^the server omits the ""Server"" response header$")]
    public async Task AssertNoServerHeader()
    {
        var (status, headers, _) = await GetAsync("/health").ConfigureAwait(false);
        Assert.Equal(200, status);
        Assert.DoesNotMatch(@"(?im)^Server\s*:", headers);
    }

    [Then("^the health endpoint reports a healthy server$")]
    public async Task AssertHealthy()
    {
        var (status, _, body) = await GetAsync("/health").ConfigureAwait(false);
        Assert.Equal(200, status);
        Assert.Equal("Healthy", body.Trim());
    }

    [Then("^the Unified role exposes the EST, ACME, CA and SCEP endpoints$")]
    public async Task UnifiedExposes()
    {
        await ExpectAsync("GET", "/.well-known/est/cacerts", 200).ConfigureAwait(false);
        await ExpectAsync("GET", "/directory", 200).ConfigureAwait(false);
        await ExpectAsync("GET", "/ca/crl", 200).ConfigureAwait(false);
        await ExpectAsync("GET", "/scep?operation=GetCACaps", 200).ConfigureAwait(false);
    }

    [Then("^the Unified role hides the RA endpoints$")]
    public async Task UnifiedHidesRa() =>
        await ExpectAsync("POST", "/ra/enroll", 404).ConfigureAwait(false);

    [Then("^the CA role exposes the CA responder$")]
    public async Task CaExposes()
    {
        await ExpectAsync("GET", "/ca/crl", 200).ConfigureAwait(false);
    }

    [Then("^the CA role hides the EST, ACME and SCEP endpoints$")]
    public async Task CaHides()
    {
        await ExpectAsync("GET", "/.well-known/est/cacerts", 404).ConfigureAwait(false);
        await ExpectAsync("GET", "/directory", 404).ConfigureAwait(false);
        await ExpectAsync("GET", "/scep?operation=GetCACaps", 404).ConfigureAwait(false);
    }

    [Then("^the RA role exposes the RA endpoints$")]
    public async Task RaExposes()
    {
        // RA routes require the ra_operator policy; without a token they exist but reject with 401.
        await ExpectAsync("POST", "/ra/enroll", 401).ConfigureAwait(false);
        await ExpectAsync("POST", "/ra/renew", 401).ConfigureAwait(false);
        await ExpectAsync("DELETE", "/ra/revoke", 401).ConfigureAwait(false);
    }

    [Then("^the RA role hides the EST, ACME, CA and SCEP endpoints$")]
    public async Task RaHides()
    {
        await ExpectAsync("GET", "/.well-known/est/cacerts", 404).ConfigureAwait(false);
        await ExpectAsync("GET", "/directory", 404).ConfigureAwait(false);
        await ExpectAsync("GET", "/ca/crl", 404).ConfigureAwait(false);
        await ExpectAsync("GET", "/scep?operation=GetCACaps", 404).ConfigureAwait(false);
    }

    [Then("^the appliance refuses to start because a hardened appliance permits only HTTPS listeners$")]
    public async Task AssertHttpGuard()
    {
        var logs = await _environment!.ServerLogsAsync().ConfigureAwait(false);
        Assert.Contains("HTTPS", logs, StringComparison.OrdinalIgnoreCase);
    }

    [Then(@"^the ""(.*)"" database reflects the appliance's relational access$")]
    public async Task DatabaseReflectsRelationalAccess(string engine)
    {
        // The client (a black-box with only curl/openssl) forced the appliance to persist a nonce via the
        // anonymous GET /new-nonce; the test then queries the database directly, proving the appliance
        // connected to and wrote to the relational backend on the shared network. Both engines keep the
        // table named Nonces; PostgreSQL quotes it, MSSQL brackets it.
        var sql = engine == "mssql"
            ? "SELECT COUNT(*) FROM [Nonces]"
            : "SELECT COUNT(*) FROM \"Nonces\"";
        var rows = await _environment!.Database!.QueryRowCountAsync(sql, CancellationToken.None).ConfigureAwait(false);
        Assert.True(rows > 0, $"Expected the {engine} database to hold a persisted nonce, found {rows}.");
    }

    [Given(@"^the ""(.*)"" appliance is deployed with the ""(.*)"" relational database$")]
    public async Task DeployWithDatabase(string role, string engine)
    {
        _environment = await IqApplianceEnvironment.StartWithDatabaseAsync(role, engine)
            .ConfigureAwait(false);
        _scenarioContext.Set(_environment);
    }

    [Given(@"^the schema for the ""(.*)"" database is migrated out of band$")]
    public Task SchemaMigratedOutofBand(string engine)
    {
        // The RelationalTestDatabase applies the schema at startup (out of band, before the appliance
        // starts), so this step documents that invariant rather than performing it in the appliance.
        Assert.NotNull(_environment?.Database);
        return Task.CompletedTask;
    }

    [When(@"^the appliance performs a database-backed role operation$")]
    public async Task AppliancePerformsDatabaseOperation()
    {
        // A GET /new-nonce is anonymous on a hardened appliance; it forces INonceService.CreateNonceAsync,
        // which persists a row to the relational NonceStore. The 204 + Replay-Nonce prove the call ran.
        await _environment!.ClientGetAsync("/new-nonce").ConfigureAwait(false);
        var (status, _, _) = await _environment.ReadProbeAsync().ConfigureAwait(false);
        Assert.Equal(204, status);
    }

    private async Task ExpectAsync(string method, string path, int expected)
    {
        var (status, _, _) = await ProbeAsync(method, path).ConfigureAwait(false);
        Assert.Equal(expected, status);
    }

    private async Task<(int Status, string Headers, string Body)> GetAsync(string path) =>
        await ProbeAsync("GET", path).ConfigureAwait(false);

    private async Task<(int Status, string Headers, string Body)> ProbeAsync(string method, string path)
    {
        if (method == "GET")
        {
            await _environment!.ClientGetAsync(path).ConfigureAwait(false);
        }
        else
        {
            await _environment!.ClientRequestAsync(method, path).ConfigureAwait(false);
        }

        return await _environment!.ReadProbeAsync().ConfigureAwait(false);
    }
}
