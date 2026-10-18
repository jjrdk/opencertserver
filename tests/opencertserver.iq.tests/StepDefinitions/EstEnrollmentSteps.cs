namespace OpenCertServer.Iq.Tests.StepDefinitions;

using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Qualifies EST using Cisco libest's estclient and independent openssl checks on Linux.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class EstEnrollmentSteps
{
    public const string FeatureTitle = "RFC 7030 EST enrollment works for a Linux device client";

    private readonly IqAcmeEnvironment _environment;
    private readonly IqAuthorityConfiguration _configuration;
    private readonly ScenarioContext _scenario;
    private readonly AcmeScenarioState _state;
    private ExecResult? _operation;
    private string _leaf = "enrolled";

    public EstEnrollmentSteps(ScenarioContext scenario, FeatureContext feature, AcmeScenarioState state)
    {
        _scenario = scenario;
        _state = state;
        _environment = scenario.Get<IqAcmeEnvironment>();
        _configuration = feature.Get<IqAuthorityConfiguration>();
    }

    private static string Server => $"https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}";

    private string Work => _state.WorkDir;

    [Given("^the hardened OpenCertServer is reachable over TLS$")]
    public async Task CheckHealth()
    {
        var result = await Run($"curl -fsS '{Server}/health'").ConfigureAwait(false);
        Assert.Equal("Healthy", result.Stdout.Trim());
    }

    [When("^the Linux client fetches the server's CA certificates with \"estclient -g\"$")]
    public async Task FetchCaCertificates()
    {
        await RunEstClient("-g", "ca", "Get CA Cert success").ConfigureAwait(false);
        await DecodePkcs7($"{Work}/ca/cacert-0-0.pkcs7", "ca").ConfigureAwait(false);
    }

    [Then("^the EST client commands return exit code 0$")]
    public void AssertExitCode()
    {
        Assert.True(_operation.HasValue, "No EST client operation was run.");
        var operation = _operation.Value;
        Assert.True(operation.ExitCode == 0,
            $"EST command exited {operation.ExitCode}:\n{operation.Stdout}\n{operation.Stderr}");
    }

    [Then("^the CA chain written to disk verifies with \"openssl verify\"$")]
    public async Task VerifyCaCertificates()
    {
        // Verify every published CA, not just the first certificate in the PKCS#7 bundle.
        await Run("""
            awk '/-----BEGIN CERTIFICATE-----/ {n++; file=sprintf("ca-%d.pem",n)}
                 file {print > file}
                 /-----END CERTIFICATE-----/ {close(file); file=""}' ca.pem
            count=0
            for ca in ca-*.pem; do
                openssl x509 -in "$ca" -noout -text | grep -F 'CA:TRUE'
                openssl verify -check_ss_sig -CAfile ca.pem "$ca"
                count=$((count+1))
            done
            test "$count" -gt 0
            """).ConfigureAwait(false);
    }

    [Given("^a hardened OpenCertServer authenticated with a JWT$")]
    public async Task CheckJwtSetup()
    {
        await CheckHealth().ConfigureAwait(false);
        Assert.NotEmpty(_scenario.Get<string>("EstToken"));
    }

    [When("^the Linux client enrolls a leaf for \"(est.example.com)\" with \"estclient -e\"$")]
    public async Task EnrollWithJwt(string domain)
    {
        Assert.Equal(IqAuthorityConfiguration.EstIdentity, domain);
        await CreateRequest("enrolled").ConfigureAwait(false);
        await RunEstClient(
            $"-e -y '{Work}/enrolled.csr' --auth-token '{_scenario.Get<string>("EstToken")}'",
            "enrolled", "enrollment rv = 0 (EST_ERR_NONE)").ConfigureAwait(false);
        await DecodePkcs7($"{Work}/enrolled/cert-0-0.pkcs7", "enrolled").ConfigureAwait(false);
        _leaf = "enrolled";
    }

    [Then("^the issued file is a valid X509 leaf decodable by \"openssl x509\"$")]
    public async Task InspectLeaf()
    {
        var result = await Run($"openssl x509 -in '{Work}/{_leaf}.pem' -noout -text").ConfigureAwait(false);
        Assert.Contains("CA:FALSE", result.Stdout, StringComparison.Ordinal);
        Assert.Contains($"DNS:{IqAuthorityConfiguration.EstIdentity}", result.Stdout, StringComparison.Ordinal);
        Assert.Contains("TLS Web Client Authentication", result.Stdout, StringComparison.Ordinal);
    }

    [Then("^the leaf chains to the published CA with \"openssl verify\"$")]
    public async Task VerifyLeaf()
    {
        await FetchCaCertificates().ConfigureAwait(false);
        await VerifyCertificate(_leaf).ConfigureAwait(false);
        await Run(
            $"openssl pkey -in '{Work}/{_leaf}.key' -pubout -out '{Work}/key.pub'"
            + $" && openssl x509 -in '{Work}/{_leaf}.pem' -pubkey -noout -out '{Work}/cert.pub'"
            + $" && cmp '{Work}/key.pub' '{Work}/cert.pub'").ConfigureAwait(false);
    }

    [Given("^a Linux device enrolls and holds a valid leaf certificate$")]
    public async Task EnrollDevice()
    {
        // This scenario performs its own initial enrollment; feature execution order is irrelevant.
        await EnrollWithJwt(IqAuthorityConfiguration.EstIdentity).ConfigureAwait(false);
        await VerifyLeaf().ConfigureAwait(false);
    }

    [When("^the Linux client re-enrolls with \"estclient -r\" presenting that leaf over mTLS$")]
    public async Task ReenrollWithMtls()
    {
        await RunEstClient(
            $"-r -c '{Work}/enrolled.pem' -k '{Work}/enrolled.key'",
            "renewed", "reenroll rv = 0 (EST_ERR_NONE)").ConfigureAwait(false);
        await DecodePkcs7($"{Work}/renewed/cert-0-0.pkcs7", "renewed").ConfigureAwait(false);
        // estclient -r renews the existing key; it has no re-key option.
        await Run($"cp '{Work}/enrolled.key' '{Work}/renewed.key'").ConfigureAwait(false);
        _leaf = "renewed";
    }

    [Then("^the re-enrolled leaf chains to the published CA$")]
    public async Task VerifyRenewedLeaf()
    {
        await InspectLeaf().ConfigureAwait(false);
        await VerifyLeaf().ConfigureAwait(false);
        var original = await Run($"openssl x509 -in '{Work}/enrolled.pem' -noout -serial").ConfigureAwait(false);
        var renewed = await Run($"openssl x509 -in '{Work}/renewed.pem' -noout -serial").ConfigureAwait(false);
        Assert.NotEqual(original.Stdout.Trim(), renewed.Stdout.Trim());
    }

    [When("^the Linux client retrieves CSR attributes with \"estclient -a\"$")]
    public async Task GetCsrAttributes()
    {
        await RunEstClient("-a", "attributes").ConfigureAwait(false);
        await Run($"test -s '{Work}/attributes/csr-0-0.base64'").ConfigureAwait(false);
    }

    [Then("^the body is a CsrAttributesResponse naming the template the client must use$")]
    public async Task VerifyCsrTemplate()
    {
        await Run(
            $"openssl base64 -d -A -in '{Work}/attributes/csr-0-0.base64' -out '{Work}/csrattrs.der'"
            + $" && openssl asn1parse -inform DER -in '{Work}/csrattrs.der'"
            + $" && python3 /usr/local/bin/est-crypto.py template '{Work}'").ConfigureAwait(false);
        // Fill in the advertised commonName requirement and prove the resulting CSR can enroll.
        await EnrollWithJwt(IqAuthorityConfiguration.EstIdentity).ConfigureAwait(false);
        await VerifyLeaf().ConfigureAwait(false);
    }

    [When("^the Linux client requests server-keygen with \"estclient -q\"$")]
    public async Task RequestServerKey()
    {
        await CreateRequest("recipient").ConfigureAwait(false);
        await RunEstClient(
            $"-q -x '{Work}/recipient.key' --common-name '{IqAuthorityConfiguration.EstIdentity}'"
            + $" --auth-token '{_scenario.Get<string>("EstToken")}'",
            "keygen", "enrollment rv = 0 (EST_ERR_NONE)").ConfigureAwait(false);
    }

    [Then("^estclient writes a PKCS#8 RSA key matching the issued certificate$")]
    public async Task VerifyServerKey()
    {
        await FetchCaCertificates().ConfigureAwait(false);
        await Run(
            $"openssl base64 -d -A -in '{Work}/keygen/key-0-0.key' -out '{Work}/generated.der'"
            + $" && openssl pkcs8 -inform DER -in '{Work}/generated.der' -nocrypt -out '{Work}/generated.key'"
            + $" && openssl rsa -inform DER -in '{Work}/generated.der' -check -noout"
            + $" && openssl pkey -inform DER -in '{Work}/generated.der' -pubout -out '{Work}/generated.pub'")
            .ConfigureAwait(false);
        await DecodePkcs7($"{Work}/keygen/cert-0-0.pkcs7", "generated").ConfigureAwait(false);
        await Run(
            $"openssl x509 -in '{Work}/generated.pem' -pubkey -noout -out '{Work}/cert.pub'"
            + $" && cmp '{Work}/generated.pub' '{Work}/cert.pub'"
            + $" && openssl pkey -in '{Work}/recipient.key' -pubout -out '{Work}/recipient.pub'")
            .ConfigureAwait(false);
        await VerifyCertificate("generated").ConfigureAwait(false);
        var generated = await Run($"cat '{Work}/generated.pub'").ConfigureAwait(false);
        var recipient = await Run($"cat '{Work}/recipient.pub'").ConfigureAwait(false);
        Assert.NotEqual(recipient.Stdout, generated.Stdout);
    }

    [Given("^a hardened OpenCertServer is configured with an EST Basic user$")]
    public async Task CheckBasicSetup()
    {
        await CheckHealth().ConfigureAwait(false);
        Assert.NotEmpty(_configuration.EstPassword);
    }

    [When("^the Linux client enrolls with \"estclient -e -u <user> -h <password> --pem-output\"$")]
    public async Task EnrollWithBasic()
    {
        await CreateRequest("basic").ConfigureAwait(false);
        await RunEstClient(
            $"-e -y '{Work}/basic.csr' -u '{IqAuthorityConfiguration.EstIdentity}'"
            + $" -h '{_configuration.EstPassword}' --pem-output",
            "basic", "enrollment rv = 0 (EST_ERR_NONE)").ConfigureAwait(false);
    }

    [Then("^estclient writes a verifiable PEM leaf certificate$")]
    public async Task VerifyPemCertificate()
    {
        await Run($"test -s '{Work}/basic/cert-0-0.pem'"
            + $" && cp '{Work}/basic/cert-0-0.pem' '{Work}/basic.pem'").ConfigureAwait(false);
        _leaf = "basic";
        await InspectLeaf().ConfigureAwait(false);
        await VerifyLeaf().ConfigureAwait(false);
    }

    private Task<ExecResult> CreateRequest(string name) => Run(
        $"openssl req -new -newkey rsa:2048 -nodes -subj '/CN={IqAuthorityConfiguration.EstIdentity}'"
        + $" -addext 'subjectAltName=DNS:{IqAuthorityConfiguration.EstIdentity}'"
        + " -addext 'keyUsage=digitalSignature,keyEncipherment' -addext 'extendedKeyUsage=clientAuth'"
        + $" -keyout '{Work}/{name}.key' -out '{Work}/{name}.csr'");

    private async Task RunEstClient(string options, string directory, string? successMarker = null)
    {
        var result = await Run($"mkdir -p '{Work}/{directory}'"
            + " && EST_OPENSSL_CACERT=/usr/local/share/ca-certificates/iq-tls-root.crt"
            + $" estclient -v -s '{IqAcmeEnvironment.ServerAlias}' -p {IqAcmeEnvironment.ServerPort}"
            + $" -w 20 -o '{Work}/{directory}' {options} </dev/null").ConfigureAwait(false);
        _operation = result;
        // The sample application returns 0 even when a protocol operation fails.
        var output = result.Stdout + result.Stderr;
        Assert.DoesNotContain("failed with code", output, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("server cert verification failed", output, StringComparison.OrdinalIgnoreCase);
        if (successMarker is not null)
        {
            Assert.Contains(successMarker, output, StringComparison.Ordinal);
        }
    }

    private Task<ExecResult> DecodePkcs7(string source, string name) => Run(
        $"openssl base64 -d -A -in '{source}' -out '{Work}/{name}.p7'"
        + $" && openssl pkcs7 -inform DER -in '{Work}/{name}.p7' -print_certs -out '{Work}/{name}.pem'");

    private async Task VerifyCertificate(string name)
    {
        var result = await Run(
            $"openssl verify -CAfile '{Work}/ca.pem' -purpose sslclient"
            + $" -verify_hostname '{IqAuthorityConfiguration.EstIdentity}' '{Work}/{name}.pem'")
            .ConfigureAwait(false);
        Assert.Contains(": OK", result.Stdout, StringComparison.Ordinal);
    }

    private async Task<ExecResult> Run(string script)
    {
        var result = await _environment.ExecClientAsync(
            $"set -euo pipefail; mkdir -p '{Work}'; cd '{Work}'; {script}").ConfigureAwait(false);
        _state.LastExec = result;
        Assert.True(result.ExitCode == 0,
            $"Linux EST command exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}");
        return result;
    }
}
