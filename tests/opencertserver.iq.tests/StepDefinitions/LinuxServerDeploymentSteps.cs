namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Text.RegularExpressions;
using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Qualifies deployment hardening through curl and OpenSSL in the Linux client container.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class LinuxServerDeploymentSteps(
    ScenarioContext scenarioContext, AcmeScenarioState state, AcmeIssuanceSteps http)
{
    public const string FeatureTitle =
        "A deployed, hardened OpenCertServer is reachable and healthy over TLS from a Linux client";

    private const string TrustRoot = "/usr/local/share/ca-certificates/iq-tls-root.crt";
    private readonly IqAcmeEnvironment _environment = scenarioContext.Get<IqAcmeEnvironment>();
    private ExecResult? _handshake;
    private string? _protocol;

    private static string Server => $"https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}";

    [Given("^a hardened OpenCertServer is running and has passed its health check$")]
    [Given("^a hardened OpenCertServer is running on TLS 1.2/1.3$")]
    public Task CheckHealth() => http.GivenAHardenedOpenCertServerIsReachable();

    [Given(@"^a hardened OpenCertServer is running on (TLS 1\.[23])$")]
    public async Task CheckModernTlsServer(string protocol)
    {
        _protocol = protocol;
        await CheckHealth().ConfigureAwait(false);
    }

    [Given(@"^the client tries to negotiate (TLS 1\.[01])$")]
    public void SelectLegacyProtocol(string protocol) => _protocol = protocol;

    [When("^the Linux client GETs \"(.*)\" over HTTPS with curl$")]
    public Task GetHttps(string path) => http.WhenTheLinuxClientGetsWithCurl(path);

    [Then("^the response body reports a healthy server$")]
    public async Task AssertHealthy()
    {
        var body = await Run($"cat '{state.BodyPath}'").ConfigureAwait(false);
        Assert.Equal("Healthy", body.Stdout.Trim());
    }

    [When(@"^the Linux client opens a (TLS 1\.[23]) connection with ""openssl s_client""$")]
    [When(@"^the Linux client attempts a (TLS 1\.[01]) handshake with ""openssl s_client""$")]
    public async Task ConnectTls(string protocol)
    {
        Assert.Equal(_protocol, protocol);
        var option = protocol switch
        {
            "TLS 1.0" => "-tls1",
            "TLS 1.1" => "-tls1_1",
            "TLS 1.2" => "-tls1_2",
            "TLS 1.3" => "-tls1_3",
            _ => throw new ArgumentOutOfRangeException(nameof(protocol), protocol, "Unsupported IQ TLS version.")
        };
        // Allow legacy ciphers locally so rejection proves the server's policy, not OpenSSL's defaults.
        var legacyCiphers = protocol is "TLS 1.0" or "TLS 1.1" ? " -cipher 'ALL:@SECLEVEL=0'" : "";
        _handshake = state.LastExec = await _environment.ExecClientAsync(
                $"mkdir -p '{state.WorkDir}' && timeout 20s openssl s_client {option}{legacyCiphers}"
                + $" -connect '{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}'"
                + $" -servername '{IqAcmeEnvironment.ServerAlias}'"
                + $" -verify_hostname '{IqAcmeEnvironment.ServerAlias}' -verify_return_error"
                + $" -CAfile '{TrustRoot}' -showcerts < /dev/null")
            .ConfigureAwait(false);
    }

    [Then("^the TLS handshake completes$")]
    public void AssertHandshake()
    {
        var result = _handshake!.Value;
        Assert.True(result.ExitCode == 0, $"TLS handshake failed:\n{result.Stdout}\n{result.Stderr}");
        var version = _protocol == "TLS 1.2" ? "TLSv1.2" : "TLSv1.3";
        Assert.Matches($@"New, {Regex.Escape(version)}, Cipher is \S+", result.Stdout);
        Assert.Contains("Verify return code: 0 (ok)", result.Stdout, StringComparison.Ordinal);
    }

    [Then("^the server presents an X.509 certificate that chains to a trusted root$")]
    public async Task AssertServerCertificate()
    {
        AssertHandshake();
        var certificate = Regex.Match(_handshake!.Value.Stdout,
            @"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----");
        Assert.True(certificate.Success, "s_client did not receive a server certificate.");
        await Run($"printf '%s\\n' '{certificate.Value}' > '{state.WorkDir}/tls-leaf.pem'").ConfigureAwait(false);
        var verify = await Run($"openssl verify -CAfile '{TrustRoot}' -purpose sslserver"
                               + $" -verify_hostname '{IqAcmeEnvironment.ServerAlias}' '{state.WorkDir}/tls-leaf.pem'")
            .ConfigureAwait(false);
        Assert.Contains(": OK", verify.Stdout, StringComparison.Ordinal);
    }

    [Then("^the connection is refused$")]
    public void AssertLegacyTlsRejected()
    {
        var result = _handshake!.Value;
        Assert.NotEqual(0, result.ExitCode);
        Assert.NotEqual(124, result.ExitCode);
        Assert.Contains("alert protocol version", result.Stderr, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("-----BEGIN CERTIFICATE-----", result.Stdout, StringComparison.Ordinal);
    }

    [When("^the Linux client GETs the CA certificates with \"curl -sS -D -\"$")]
    public Task GetCaHeaders() => http.WhenTheLinuxClientGetsWithCurl("/.well-known/est/cacerts");

    [Then("^the response headers contain no \"Server\" field$")]
    public void AssertNoServerHeader()
    {
        Assert.Equal(200, state.Status);
        Assert.DoesNotMatch(@"(?im)^Server\s*:", state.Headers);
    }

    [When("^the Linux client GETs the health endpoint over plain HTTP with curl$")]
    public async Task GetHttpHealth()
    {
        var response = await Run(
                $"curl -sS --max-time 20 -D '{state.WorkDir}/http-headers' -o /dev/null -w '%{{http_code}}'"
                + $" 'http://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.HttpPort}/health'")
            .ConfigureAwait(false);
        state.Status = int.Parse(response.Stdout.Trim(), System.Globalization.CultureInfo.InvariantCulture);
        var headers = await Run($"cat '{state.WorkDir}/http-headers'").ConfigureAwait(false);
        state.Headers = headers.Stdout;
    }

    [Then("^the response is an HTTP 3xx redirect to the HTTPS endpoint$")]
    public async Task AssertHttpsRedirect()
    {
        Assert.True(state.Status is >= 300 and < 400, $"Expected a redirect, got HTTP {state.Status}.");
        var location = Regex.Match(state.Headers, @"(?im)^Location:\s*(\S+)\s*$");
        Assert.True(location.Success, $"Missing Location header:\n{state.Headers}");
        Assert.Equal($"{Server}/health", location.Groups[1].Value);
        var response = await Run($"curl -fsS --max-time 20 '{location.Groups[1].Value}'").ConfigureAwait(false);
        Assert.Equal("Healthy", response.Stdout.Trim());
    }

    [Then("^the response body decodes to a non-empty X.509 chain with \"openssl\"$")]
    public async Task AssertPublishedChain()
    {
        Assert.Equal(200, state.Status);
        await Run($"base64 -d '{state.BodyPath}' > '{state.WorkDir}/ca.p7b'"
                  + $" && openssl pkcs7 -inform DER -in '{state.WorkDir}/ca.p7b'"
                  + $" -print_certs -out '{state.WorkDir}/ca.pem'").ConfigureAwait(false);
        var certificates = await Run(
            $"openssl crl2pkcs7 -nocrl -certfile '{state.WorkDir}/ca.pem'"
            + " | openssl pkcs7 -print_certs -text -noout").ConfigureAwait(false);
        Assert.Contains("Certificate:", certificates.Stdout, StringComparison.Ordinal);
        Assert.Contains("CA:TRUE", certificates.Stdout, StringComparison.Ordinal);
        var verify = await Run(
            $"openssl verify -CAfile '{state.WorkDir}/ca.pem' '{state.WorkDir}/ca.pem'").ConfigureAwait(false);
        Assert.Contains(": OK", verify.Stdout, StringComparison.Ordinal);
    }

    private async Task<ExecResult> Run(string script)
    {
        var result = await _environment.ExecClientAsync(
            $"set -euo pipefail; mkdir -p '{state.WorkDir}'; {script}").ConfigureAwait(false);
        state.LastExec = result;
        Assert.True(result.ExitCode == 0,
            $"Client command failed ({result.ExitCode}):\n{script}\n{result.Stdout}\n{result.Stderr}");
        return result;
    }
}
