namespace OpenCertServer.Iq.Tests.StepDefinitions;

using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Qualifies SCEP using sscep and independent openssl checks on Linux.</summary>
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

    private const int BridgePort = 8089;

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

    [When("^sscep enrolls \"([^\"]+)\" with the right challenge$")]
    public Task EnrollWithChallenge(string device) => Enroll(device, Challenge, "/scep");

    [When("^sscep enrolls \"([^\"]+)\" with the challenge \"([^\"]+)\"$")]
    public Task EnrollWithOtherChallenge(string device, string challenge) => Enroll(device, challenge, "/scep");

    [When("^sscep enrolls \"([^\"]+)\" with the right challenge at \"([^\"]+)\"$")]
    public Task EnrollAtPath(string device, string path) => Enroll(device, Challenge, path);

    [When("^sscep enrolls \"([^\"]+)\" with the right challenge and the request encrypted with \"([^\"]+)\"$")]
    public Task EnrollEncrypted(string device, string encryption) =>
        Enroll(device, Challenge, "/scep", encryption);

    [Then("^sscep exits with code 0$")]
    public void AssertSuccess()
    {
        Assert.True(_operation.HasValue, "sscep was not run.");
        Assert.True(_operation.Value.ExitCode == 0,
            $"sscep exited {_operation.Value.ExitCode}:\n{_operation.Value.Stdout}\n{_operation.Value.Stderr}");
    }

    [Then("^the certificate names \"([^\"]+)\" and chains to the published CA with \"openssl verify\"$")]
    public async Task AssertCertificate(string device)
    {
        var subject = await Run($"openssl x509 -in '{Device}/cert.pem' -noout -subject -nameopt RFC2253")
            .ConfigureAwait(false);
        Assert.Contains($"CN={device}", subject.Stdout, StringComparison.Ordinal);
        await VerifyChain().ConfigureAwait(false);
    }

    [Then("^sscep fails with a SCEP FAILURE \"(badRequest|badAlg)\"$")]
    public void AssertFailure(string failInfo)
    {
        Assert.True(_operation.HasValue, "sscep was not run.");
        var operation = _operation.Value;
        // sscep reads the signed CertRep and exits with 70 + failInfo (badAlg 70, badRequest 72) -
        // not with a transport or TLS error, which would mean the server was never asked.
        var expected = failInfo == "badAlg" ? 70 : 72;
        Assert.True(operation.ExitCode == expected,
            $"sscep exited {operation.ExitCode}, expected {expected}:\n{operation.Stdout}\n{operation.Stderr}");
        Assert.Contains("pkistatus: FAILURE", operation.Stdout + operation.Stderr, StringComparison.Ordinal);
    }

    [Then("^no certificate is written$")]
    public async Task AssertNoCertificate() =>
        await Run($"test ! -e '{Device}/cert.pem'").ConfigureAwait(false);

    [Given("^sscep holds a certificate for \"([^\"]+)\"$")]
    public async Task HoldCertificate(string device)
    {
        await CheckHealth().ConfigureAwait(false);
        await Enroll(device, Challenge, "/scep").ConfigureAwait(false);
        AssertSuccess();
        _previousSerial = (await Run($"openssl x509 -in '{Device}/cert.pem' -noout -serial").ConfigureAwait(false))
            .Stdout.Trim();
    }

    [When("^sscep enrolls again with a new key, signing with that certificate$")]
    public async Task EnrollAgain()
    {
        // sscep has no RenewalReq: it signs a new PKCSReq with the certificate it holds (-K/-O).
        await Run($"cd '{Device}' && mv key.pem old-key.pem && mv cert.pem old-cert.pem").ConfigureAwait(false);
        _operation = await Sscep("/scep", Challenge, "aes", signWithHeld: true).ConfigureAwait(false);
    }

    [Then("^the renewed certificate has a new serial number and chains to the published CA$")]
    public async Task AssertRenewed()
    {
        var serial = (await Run($"openssl x509 -in '{Device}/cert.pem' -noout -serial").ConfigureAwait(false))
            .Stdout.Trim();
        Assert.NotEqual(_previousSerial, serial);
        await VerifyChain().ConfigureAwait(false);
    }

    private async Task Enroll(string device, string challenge, string path, string encryption = "aes")
    {
        _device = device;
        _operation = await Sscep(path, challenge, encryption).ConfigureAwait(false);
    }

    private async Task<ExecResult> Sscep(string path, string challenge, string encryption, bool signWithHeld = false)
    {
        await StartBridge().ConfigureAwait(false);
        var url = $"http://127.0.0.1:{BridgePort}{path}";
        var signer = signWithHeld ? " -K old-key.pem -O old-cert.pem" : "";
        // The RA from GetCACert (key encipherment, not a CA) decrypts the request and signs the reply.
        // The CSR carries the challenge as challengePassword (RFC 8894, 2.2).
        var result = await _environment.ExecClientAsync(
            $$"""
            set -uo pipefail; mkdir -p '{{Device}}'; cd '{{Device}}'
            rm -f ca.crt-*
            sscep getca -u '{{url}}' -c ca.crt >getca.log 2>&1 || { cat getca.log; exit 90; }
            for c in ca.crt-*; do
                text=$(openssl x509 -in "$c" -noout -text)
                if ! grep -qF 'CA:TRUE' <<<"$text" && grep -qF 'Key Encipherment' <<<"$text"; then cp "$c" ra.pem; fi
            done
            test -s ra.pem || { echo 'no RA certificate in GetCACert'; exit 91; }
            printf '[req]\nprompt = no\ndistinguished_name = dn\nattributes = attrs\n[dn]\nCN = %s\n[attrs]\nchallengePassword = %s\n' \
                '{{_device}}' '{{challenge}}' > req.cnf
            openssl req -new -newkey rsa:2048 -nodes -keyout key.pem -out req.pem -config req.cnf 2>/dev/null
            sscep enroll -u '{{url}}' -c ra.pem -k key.pem -r req.pem -l cert.pem -E {{encryption}} -S sha256{{signer}}
            """)
            .ConfigureAwait(false);
        _state.LastExec = result;
        return result;
    }

    // sscep speaks plain HTTP. socat carries it to the hardened server over TLS and verifies the
    // server certificate against the system bundle - the same trust every other client here uses.
    private async Task StartBridge() =>
        await Run($"""
            if ! (exec 3<>/dev/tcp/127.0.0.1/{BridgePort}) 2>/dev/null; then
                setsid nohup socat TCP-LISTEN:{BridgePort},bind=127.0.0.1,reuseaddr,fork \
                    OPENSSL:{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort},cafile=/etc/ssl/certs/ca-certificates.crt,verify=1 \
                    >/tmp/socat-scep.log 2>&1 </dev/null &
                for _ in $(seq 1 50); do (exec 3<>/dev/tcp/127.0.0.1/{BridgePort}) 2>/dev/null && break; sleep 0.1; done
            fi
            (exec 3<>/dev/tcp/127.0.0.1/{BridgePort})
            """).ConfigureAwait(false);

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
