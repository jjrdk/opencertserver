namespace OpenCertServer.Iq.Tests.StepDefinitions;

using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Qualifies SCEP using micromdm's scepclient and independent openssl checks on Linux.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class ScepEnrollmentSteps
{
    public const string FeatureTitle = "RFC 8894 SCEP enrollment works for a Linux device client";

    /// <summary>The shared challenge the server is started with for this feature.</summary>
    public const string Challenge = "iq-scep-challenge";

    private readonly IqAcmeEnvironment _environment;
    private readonly AcmeScenarioState _state;
    private ExecResult? _operation;
    private string _device = "";
    private string? _previousSerial;

    public ScepEnrollmentSteps(ScenarioContext scenario, AcmeScenarioState state)
    {
        _state = state;
        _environment = scenario.Get<IqAcmeEnvironment>();
    }

    private static string Server => $"https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}";

    private string Work => _state.WorkDir;

    private string Device => $"{Work}/{_device}";

    [Given("^the hardened OpenCertServer is reachable over TLS$")]
    public async Task CheckHealth()
    {
        var result = await Run($"curl -fsS '{Server}/health'").ConfigureAwait(false);
        Assert.Equal("Healthy", result.Stdout.Trim());
    }

    [When("^the Linux client asks for the SCEP capabilities$")]
    public async Task GetCapabilities()
    {
        _operation = await Run($"curl -fsS '{Server}/scep?operation=GetCACaps'").ConfigureAwait(false);
    }

    [Then("^the capabilities include POSTPKIOperation, SHA-256, AES and Renewal$")]
    public void AssertCapabilities()
    {
        var capabilities = _operation!.Value.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var expected in new[] { "POSTPKIOperation", "SHA-256", "AES", "Renewal" })
        {
            Assert.Contains(expected, capabilities);
        }
    }

    [When("^the Linux client fetches the SCEP CA certificates$")]
    public Task FetchCaCertificates() => FetchBundle();

    [Then("^the bundle holds an RA certificate for key encipherment and a CA certificate$")]
    public async Task AssertBundle()
    {
        // Every certificate on its own: the RA encrypts, the CA signs - never the same one.
        await Run("""
            awk '/-----BEGIN CERTIFICATE-----/ {n++; file=sprintf("bundle-%d.pem",n)}
                 file {print > file}
                 /-----END CERTIFICATE-----/ {close(file); file=""}' bundle.pem
            ra=0; ca=0
            for c in bundle-*.pem; do
                text=$(openssl x509 -in "$c" -noout -text)
                if grep -qF 'CA:TRUE' <<<"$text"; then ca=$((ca+1));
                elif grep -qF 'Key Encipherment' <<<"$text"; then ra=$((ra+1)); fi
            done
            test "$ra" -ge 1
            test "$ca" -ge 1
            """).ConfigureAwait(false);
    }

    [When("^scepclient enrolls \"([^\"]+)\" with the right challenge$")]
    public Task EnrollWithChallenge(string device) => Enroll(device, Challenge, "/scep");

    [When("^scepclient enrolls \"([^\"]+)\" with the challenge \"([^\"]+)\"$")]
    public Task EnrollWithOtherChallenge(string device, string challenge) => Enroll(device, challenge, "/scep");

    [When("^scepclient enrolls \"([^\"]+)\" with the right challenge at \"([^\"]+)\"$")]
    public Task EnrollAtPath(string device, string path) => Enroll(device, Challenge, path);

    [Then("^scepclient exits with code 0$")]
    public void AssertSuccess()
    {
        Assert.True(_operation.HasValue, "scepclient was not run.");
        Assert.True(_operation.Value.ExitCode == 0,
            $"scepclient exited {_operation.Value.ExitCode}:\n{_operation.Value.Stdout}\n{_operation.Value.Stderr}");
    }

    [Then("^the certificate names \"([^\"]+)\" and chains to the published CA with \"openssl verify\"$")]
    public async Task AssertCertificate(string device)
    {
        var subject = await Run($"openssl x509 -in '{Device}/cert.pem' -noout -subject -nameopt RFC2253")
            .ConfigureAwait(false);
        Assert.Contains($"CN={device}", subject.Stdout, StringComparison.Ordinal);
        await VerifyChain().ConfigureAwait(false);
    }

    [Then("^scepclient fails with a SCEP FAILURE$")]
    public void AssertFailure()
    {
        Assert.True(_operation.HasValue, "scepclient was not run.");
        var operation = _operation.Value;
        Assert.NotEqual(0, operation.ExitCode);
        // scepclient reports a CertRep FAILURE as "PKCSReq request failed, failInfo: …" - not a
        // transport or TLS error, which would mean the server was never asked.
        Assert.Contains("request failed, failInfo", operation.Stdout + operation.Stderr, StringComparison.Ordinal);
    }

    [Then("^no certificate is written$")]
    public async Task AssertNoCertificate() =>
        await Run($"test ! -e '{Device}/cert.pem'").ConfigureAwait(false);

    [Given("^scepclient holds a certificate for \"([^\"]+)\"$")]
    public async Task HoldCertificate(string device)
    {
        await CheckHealth().ConfigureAwait(false);
        await Enroll(device, Challenge, "/scep").ConfigureAwait(false);
        AssertSuccess();
        _previousSerial = (await Run($"openssl x509 -in '{Device}/cert.pem' -noout -serial").ConfigureAwait(false))
            .Stdout.Trim();
    }

    [When("^scepclient runs again with that certificate$")]
    public async Task RunAgain()
    {
        // With cert.pem present, scepclient sends a RenewalReq signed with it and no challenge.
        _operation = await ScepClient("/scep", challenge: null).ConfigureAwait(false);
    }

    [Then("^the renewed certificate has a new serial number and chains to the published CA$")]
    public async Task AssertRenewed()
    {
        var serial = (await Run($"openssl x509 -in '{Device}/cert.pem' -noout -serial").ConfigureAwait(false))
            .Stdout.Trim();
        Assert.NotEqual(_previousSerial, serial);
        await VerifyChain().ConfigureAwait(false);
    }

    private async Task Enroll(string device, string challenge, string path)
    {
        _device = device;
        _operation = await ScepClient(path, challenge).ConfigureAwait(false);
    }

    private async Task<ExecResult> ScepClient(string path, string? challenge)
    {
        var challengeArgument = challenge is null ? "" : $" -challenge '{challenge}'";
        // scepclient keeps its key, CSR and self-signed signer next to the key file.
        var result = await _environment.ExecClientAsync(
            $"set -uo pipefail; mkdir -p '{Device}'; cd '{Device}'; "
            + $"scepclient -server-url '{Server}{path}'{challengeArgument} -cn '{_device}'"
            + $" -private-key '{Device}/key.pem' -certificate '{Device}/cert.pem' -key-encipherment-selector")
            .ConfigureAwait(false);
        _state.LastExec = result;
        return result;
    }

    private async Task FetchBundle()
    {
        await Run($"curl -fsS -o bundle.der '{Server}/scep?operation=GetCACert'"
            + " && openssl pkcs7 -inform DER -in bundle.der -print_certs -out bundle.pem").ConfigureAwait(false);
    }

    private async Task VerifyChain()
    {
        // The chain from GetCACert, without the RA: only CA:TRUE certificates may anchor the leaf.
        await FetchBundle().ConfigureAwait(false);
        await Run($$"""
            awk '/-----BEGIN CERTIFICATE-----/ {n++; file=sprintf("chain-%d.pem",n)}
                 file {print > file}
                 /-----END CERTIFICATE-----/ {close(file); file=""}' bundle.pem
            : > ca.pem
            for c in chain-*.pem; do
                if openssl x509 -in "$c" -noout -text | grep -qF 'CA:TRUE'; then cat "$c" >> ca.pem; fi
            done
            test -s ca.pem
            openssl verify -CAfile ca.pem '{{Device}}/cert.pem'
            """).ConfigureAwait(false);
    }

    private async Task<ExecResult> Run(string script)
    {
        var result = await _environment.ExecClientAsync(
            $"set -euo pipefail; mkdir -p '{Work}'; cd '{Work}'; {script}").ConfigureAwait(false);
        _state.LastExec = result;
        Assert.True(result.ExitCode == 0,
            $"Linux SCEP command exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}");
        return result;
    }
}
