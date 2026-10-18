namespace OpenCertServer.Iq.Tests.StepDefinitions;

using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Qualifies the published Linux CLI through real processes and independent cryptographic checks.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class OpenCertCliSteps(ScenarioContext scenario, AcmeScenarioState state)
{
    public const string FeatureTitle = "The opencert CLI runs as a Linux binary that drives the server";

    private const string Password = "IQ CLI password with spaces";
    private readonly IqAcmeEnvironment _environment = scenario.Get<IqAcmeEnvironment>();
    private ExecResult? _operation;

    private static string Server => $"https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}";

    private static string EstServerOptions => $"--url '{Server}' --ta-mode explicit"
        + " --est-ca /usr/local/share/ca-certificates/iq-tls-root.crt";

    private string Work => state.WorkDir;

    [BeforeScenario(Order = 10)]
    public Task CheckLinuxBinary() => Run("""
        python3 - <<'PY'
        import pathlib, platform, shutil
        assert platform.system() == "Linux"
        binary = pathlib.Path(shutil.which("opencert"))
        with binary.open("rb") as executable:
            assert executable.read(4) == b"\x7fELF", "opencert is not a Linux ELF executable"
        PY
        """);

    [When("^the Linux client runs \"opencert hash-password\" with a password$")]
    public async Task HashPassword()
    {
        _operation = await Run($"printf '%s' '{Password}' | timeout 60s opencert hash-password | tee hash.txt")
            .ConfigureAwait(false);
    }

    [Then("^the output is a PBKDF2-SHA256 hash$")]
    public async Task VerifyPasswordHash()
    {
        AssertOperationSucceeded();
        await Run($$"""
            python3 - <<'PY'
            import base64, hashlib, hmac, pathlib
            algorithm, rounds, salt, digest = pathlib.Path("hash.txt").read_text().strip().split("$")
            assert algorithm == "pbkdf2-sha256"
            assert int(rounds) == 600000
            salt = base64.b64decode(salt, validate=True)
            digest = base64.b64decode(digest, validate=True)
            assert len(salt) == 16 and len(digest) == 32
            expected = hashlib.pbkdf2_hmac("sha256", b"{{Password}}", salt, int(rounds), len(digest))
            assert hmac.compare_digest(expected, digest), "hash does not verify the supplied password"
            PY
            """).ConfigureAwait(false);
    }

    [When("^the Linux client runs \"opencert generate-keys\" then \"opencert create-csr\"$")]
    public async Task BuildKeyAndCsr()
    {
        await GenerateKeys().ConfigureAwait(false);
        var result = await RunCli("create-csr --private-key private.pem --out request.pem"
            + $" --CN '{IqAuthorityConfiguration.EstIdentity}' --san '{IqAuthorityConfiguration.EstIdentity}'"
            + " --key-usage digitalSignature,keyEncipherment --eku clientAuth").ConfigureAwait(false);
        Assert.Contains("CSR written to request.pem", result.Stdout, StringComparison.Ordinal);
    }

    [Then("^a key file and a PKCS#10 CSR are produced$")]
    public async Task InspectKeyAndCsr()
    {
        AssertOperationSucceeded();
        var result = await Run("""
            test -s private.pem && test -s public.pem && test -s request.pem
            openssl pkey -in private.pem -check -noout
            openssl pkey -in private.pem -pubout -outform DER -out key.der
            openssl pkey -pubin -in public.pem -outform DER -out public.der
            cmp key.der public.der
            openssl req -in request.pem -pubkey -noout | openssl pkey -pubin -outform DER -out request.der
            cmp key.der request.der
            openssl req -in request.pem -noout -subject -text
            """).ConfigureAwait(false);
        Assert.Contains($"CN={IqAuthorityConfiguration.EstIdentity}",
            result.Stdout.Replace("CN = ", "CN=", StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.Contains($"DNS:{IqAuthorityConfiguration.EstIdentity}", result.Stdout, StringComparison.Ordinal);
    }

    [Then("^the CSR is verifiable with \"openssl req -verify\"$")]
    public async Task VerifyCsrSignature()
    {
        var result = await Run("openssl req -in request.pem -verify -noout").ConfigureAwait(false);
        Assert.Contains("verify OK", result.Stdout + result.Stderr, StringComparison.Ordinal);
    }

    [Given("^a certificate file on the Linux client$")]
    public Task CreateCertificate() => Run(
        "openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=cli-print.example.com/O=IQ CLI'"
        + " -keyout print.key -out print.pem");

    [When("^the Linux client runs \"opencert print-cert\" on it$")]
    public Task PrintCertificate() => RunCli("print-cert --cert print.pem");

    [Then("^the output contains the certificate's subject and validity$")]
    public async Task VerifyPrintedCertificate()
    {
        AssertOperationSucceeded();
        await Run("""
            python3 - <<'PY'
            import datetime, pathlib, re, subprocess
            output = pathlib.Path("cli.stdout").read_text()
            subject = re.search(r"^\s*Subject:\s*\n(.*?)(?=^\s*Subject Public Key Info:)",
                                output, re.M | re.S)
            assert subject and "cli-print.example.com" in subject[1] and "IQ CLI" in subject[1]
            assert "Validity" in output
            dates = subprocess.check_output(
                ["openssl", "x509", "-in", "print.pem", "-noout", "-dates"], text=True)
            for field, label in (("notBefore", "Not Before"), ("notAfter", "Not After")):
                expected = re.search(rf"^{field}=(.+)$", dates, re.M)
                actual = re.search(rf"{label}\s*:\s*(.+)", output)
                assert expected and actual
                parse = lambda value: datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y GMT")
                assert parse(expected[1]) == parse(actual[1]), f"{field} does not match the certificate"
            PY
            """).ConfigureAwait(false);
    }

    [Given("^a hardened OpenCertServer reached by the Linux client$")]
    public async Task CheckHealth()
    {
        var result = await Run($"curl --max-time 20 -fsS '{Server}/health'").ConfigureAwait(false);
        Assert.Equal("Healthy", result.Stdout.Trim());
    }

    [When("^the Linux client runs \"opencert est-enroll\" with \"opencert\"-generated keys against the server$")]
    public async Task Enroll()
    {
        await GenerateKeys().ConfigureAwait(false);
        var result = await RunCli(
            $"est-enroll {EstServerOptions} --profile rsa --private-key private.pem --out enrolled.pem"
            + $" --CN '{IqAuthorityConfiguration.EstIdentity}' --key-usage digitalSignature,keyEncipherment"
            + $" --auth 'Bearer {scenario.Get<string>("EstToken")}'").ConfigureAwait(false);
        Assert.Contains("EST enrollment succeeded", result.Stdout, StringComparison.Ordinal);
    }

    [Then("^opencert exits 0 and writes a certificate to disk$")]
    public async Task VerifyEnrollment()
    {
        AssertOperationSucceeded();
        await VerifyLeaf("enrolled.pem").ConfigureAwait(false);
    }

    [When("^the Linux client runs \"opencert est-server-certificates\"$")]
    public Task FetchCaChain() => RunCli($"est-server-certificates {EstServerOptions}");

    [Then("^the output contains \"-----BEGIN CERTIFICATE-----\"$")]
    public async Task VerifyCaChain()
    {
        AssertOperationSucceeded();
        Assert.Contains("-----BEGIN CERTIFICATE-----", _operation!.Value.Stdout, StringComparison.Ordinal);
        await FetchPublishedCa().ConfigureAwait(false);
        await Run("""
            mkdir cli-ca published-ca
            for source in cli.stdout published.pem; do
                directory=cli-ca
                if [ "$source" = published.pem ]; then directory=published-ca; fi
                awk -v directory="$directory" '
                    /-----BEGIN CERTIFICATE-----/ {n++; file=sprintf("%s/ca-%d.pem",directory,n)}
                    file {print > file}
                    /-----END CERTIFICATE-----/ {close(file); file=""}' "$source"
            done
            for directory in cli-ca published-ca; do
                for certificate in "$directory"/*.pem; do
                    openssl x509 -in "$certificate" -noout -text | grep -F 'CA:TRUE'
                    openssl verify -check_ss_sig -CAfile published.pem "$certificate"
                    openssl x509 -in "$certificate" -outform DER | sha256sum | cut -d ' ' -f 1
                done > "$directory/results"
                grep -E '^[0-9a-f]{64}$' "$directory/results" | sort > "$directory/fingerprints"
                test -s "$directory/fingerprints"
            done
            cmp cli-ca/fingerprints published-ca/fingerprints
            """).ConfigureAwait(false);
    }

    [Given("^a Linux client holding a certificate obtained by \"opencert est-enroll\"$")]
    public async Task EnrollForRenewal()
    {
        await CheckHealth().ConfigureAwait(false);
        await Enroll().ConfigureAwait(false);
        await VerifyEnrollment().ConfigureAwait(false);
    }

    [When("^the Linux client runs \"opencert est-reenroll\" with that certificate$")]
    public async Task Reenroll()
    {
        var result = await RunCli(
            $"est-reenroll {EstServerOptions} --profile rsa --private-key private.pem"
            + " --cert enrolled.pem --out renewed.pem").ConfigureAwait(false);
        Assert.Contains("EST re-enrollment succeeded", result.Stdout, StringComparison.Ordinal);
    }

    [Then("^opencert exits 0 and writes a renewed certificate to disk$")]
    public async Task VerifyRenewal()
    {
        AssertOperationSucceeded();
        await VerifyLeaf("renewed.pem").ConfigureAwait(false);
        var original = await Run("openssl x509 -in enrolled.pem -noout -serial -subject").ConfigureAwait(false);
        var renewed = await Run("openssl x509 -in renewed.pem -noout -serial -subject").ConfigureAwait(false);
        var originalLines = original.Stdout.Trim().Split('\n');
        var renewedLines = renewed.Stdout.Trim().Split('\n');
        Assert.NotEqual(originalLines[0], renewedLines[0]);
        Assert.Equal(originalLines[1], renewedLines[1]);
    }

    private async Task GenerateKeys()
    {
        var result = await RunCli(
            "generate-keys --algorithm rsa --private-key-out private.pem --public-key-out public.pem")
            .ConfigureAwait(false);
        Assert.Contains("Generated RSA-3072 key pair.", result.Stdout, StringComparison.Ordinal);
    }

    private Task<ExecResult> FetchPublishedCa() => Run(
        $"curl --max-time 20 -fsS '{Server}/.well-known/est/cacerts' -o published.b64"
        + " && openssl base64 -d -A -in published.b64 -out published.p7"
        + " && openssl pkcs7 -inform DER -in published.p7 -print_certs -out published.pem");

    private async Task VerifyLeaf(string name)
    {
        await FetchPublishedCa().ConfigureAwait(false);
        var result = await Run(
            $"test -s '{name}' && openssl x509 -in '{name}' -noout -text"
            + $" && openssl verify -CAfile published.pem -purpose sslclient"
            + $" -verify_hostname '{IqAuthorityConfiguration.EstIdentity}' '{name}'"
            + " && openssl pkey -in private.pem -pubout -out key.pub"
            + $" && openssl x509 -in '{name}' -pubkey -noout -out cert.pub"
            + " && cmp key.pub cert.pub").ConfigureAwait(false);
        Assert.Contains("CA:FALSE", result.Stdout, StringComparison.Ordinal);
        Assert.Contains("TLS Web Client Authentication", result.Stdout, StringComparison.Ordinal);
        Assert.Contains(": OK", result.Stdout, StringComparison.Ordinal);
    }

    private void AssertOperationSucceeded()
    {
        Assert.True(_operation.HasValue, "No opencert operation was run.");
        Assert.True(_operation.Value.ExitCode == 0,
            $"opencert exited {_operation.Value.ExitCode}:\n{_operation.Value.Stdout}\n{_operation.Value.Stderr}");
    }

    private async Task<ExecResult> RunCli(string arguments)
    {
        var result = await Run($"timeout 60s opencert {arguments} </dev/null | tee cli.stdout").ConfigureAwait(false);
        _operation = result;
        return result;
    }

    private async Task<ExecResult> Run(string script)
    {
        var result = await _environment.ExecClientAsync(
            $"set -euo pipefail; mkdir -p '{Work}'; cd '{Work}'; {script}").ConfigureAwait(false);
        state.LastExec = result;
        Assert.True(result.ExitCode == 0,
            $"Linux CLI check exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}");
        return result;
    }
}
