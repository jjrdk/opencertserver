namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Text.RegularExpressions;
using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Qualifies profile-controlled issuance through Linux estclient and independent OpenSSL checks.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class ProfileIssuanceSteps
{
    public const string FeatureTitle = "Profile-controlled certificate content is what the client receives";

    private readonly IqAcmeEnvironment _environment;
    private readonly IqAuthorityConfiguration _configuration;
    private readonly AcmeScenarioState _state;
    private string _algorithm = "RSA";
    private string _certificateText = "";
    private string _profile = "rsa";
    private string _rejectionOutput = "";

    public ProfileIssuanceSteps(ScenarioContext scenario, FeatureContext feature, AcmeScenarioState state)
    {
        _environment = scenario.Get<IqAcmeEnvironment>();
        _configuration = feature.Get<IqAuthorityConfiguration>();
        _state = state;
    }

    private string Work => _state.WorkDir;

    [Given("^a profile that fixes certificatePolicies to include policy \"(1\\.3\\.6\\.1\\.4\\.1\\.999)\"$")]
    public Task GivenPolicy(string policy)
    {
        Assert.Equal("1.3.6.1.4.1.999", policy);
        return CheckHealth();
    }

    [Given("^a profile that fixes keyUsage to \"(keyEncipherment,dataEncipherment)\"$")]
    public Task GivenKeyUsage(string usage)
    {
        Assert.Equal("keyEncipherment,dataEncipherment", usage);
        return CheckHealth();
    }

    [Given("^a profile that fixes extendedKeyUsage to \"(serverAuth,codeSigning)\"$")]
    public Task GivenExtendedKeyUsage(string usage)
    {
        Assert.Equal("serverAuth,codeSigning", usage);
        return CheckHealth();
    }

    [Given("^a profile that does not authorise CA issuance$")]
    public Task GivenNonCaProfile() => CheckHealth();

    [Given("^a hardened OpenCertServer with a (RSA|EC) profile$")]
    public Task GivenAlgorithm(string algorithm)
    {
        _algorithm = algorithm;
        _profile = algorithm == "RSA" ? "rsa" : "ecdsa";
        return CheckHealth();
    }

    [When("^the Linux client enrolls a certificate from that profile with \"est-client\"$")]
    public Task EnrollPolicy() => Enroll();

    [When("^the Linux client enrolls from that profile asking for \"(digitalSignature|clientAuth)\" in the CSR$")]
    public Task EnrollConflictingUsage(string usage) =>
        usage == "digitalSignature" ? Enroll(keyUsage: usage) : Enroll(extendedKeyUsage: usage);

    [When("^the Linux client enrolls from that profile with \"basicConstraints: CA:TRUE\" in the CSR$")]
    public Task EnrollCaRequest() => Enroll(requestCa: true);

    [When("^the Linux client enrolls from the (RSA|EC) profile and inspects the result with \"openssl x509 -text\"$")]
    public async Task EnrollAlgorithm(string algorithm)
    {
        Assert.Equal(_algorithm, algorithm);
        await Enroll().ConfigureAwait(false);
        await InspectCertificate().ConfigureAwait(false);
    }

    [When("^inspects the issued certificate with \"openssl x509 -text\"$")]
    public async Task InspectCertificate()
    {
        var result = await Run("openssl x509 -in issued.pem -noout -text").ConfigureAwait(false);
        _certificateText = result.Stdout;
    }

    [Then("^the certificatePolicies extension contains \"(.*)\"$")]
    public void AssertPolicies(string policy) =>
        Assert.Equal([$"Policy: {policy}"], Extension(_certificateText, "X509v3 Certificate Policies"));

    [Then("^the critical keyUsage is \"(keyEncipherment,dataEncipherment)\"$")]
    public void AssertKeyUsage(string usage)
    {
        Assert.Equal("keyEncipherment,dataEncipherment", usage);
        Assert.Equal(["Key Encipherment, Data Encipherment"],
            Extension(_certificateText, "X509v3 Key Usage", critical: true));
    }

    [Then("^the extendedKeyUsage is \"(serverAuth,codeSigning)\"$")]
    public void AssertExtendedKeyUsage(string usage)
    {
        Assert.Equal("serverAuth,codeSigning", usage);
        Assert.Equal(["TLS Web Server Authentication, Code Signing"],
            Extension(_certificateText, "X509v3 Extended Key Usage"));
    }

    [Then("^enrollment is rejected with HTTP 400 because CA issuance is not authorised$")]
    public async Task AssertCaRequestRejected()
    {
        Assert.Contains("HTTP status 400 received", _rejectionOutput, StringComparison.Ordinal);
        Assert.Contains("enrollment rv = 13 (EST_ERR_HTTP_BAD_REQ)", _rejectionOutput, StringComparison.Ordinal);
        Assert.DoesNotContain("enrollment rv = 0 (EST_ERR_NONE)", _rejectionOutput, StringComparison.Ordinal);

        // libest omits the error body; repeat the same signed CSR to qualify the rejection reason.
        var result = await Run(
            "openssl req -in request.csr -outform DER -out request.der"
            + " && openssl base64 -A -in request.der -out request.b64"
            + $" && curl -sS --max-time 30 --user '{IqAuthorityConfiguration.EstIdentity}:{_configuration.EstPassword}'"
            + " -H 'Content-Type: application/pkcs10' --data-binary @request.b64"
            + " --write-out '\\n%{http_code}'"
            + $" 'https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}/.well-known/est/{_profile}/simpleenroll'")
            .ConfigureAwait(false);
        Assert.Equal("CSR must not request CA:TRUE in basicConstraints\n400", result.Stdout.Trim());
    }

    [Then("^the Linux client receives no issued certificate$")]
    public Task AssertNoCertificate() => Run(
        "test -z \"$(find enrollment -type f -name 'cert-*' -print)\" && test ! -e issued.pem");

    [Then("^the certificate's public key is a (RSA|EC) key$")]
    public void AssertPublicKey(string algorithm)
    {
        Assert.Equal(_algorithm, algorithm);
        var oidName = algorithm == "RSA" ? "rsaEncryption" : "id-ecPublicKey";
        Assert.Matches($@"(?m)^\s*Public Key Algorithm: {Regex.Escape(oidName)}\r?$", _certificateText);
    }

    [Then("^the certificate chains to the published CA$")]
    public async Task VerifyChain()
    {
        var result = await Run(
            $"openssl verify -CAfile ca.pem -verify_hostname '{IqAuthorityConfiguration.EstIdentity}' issued.pem")
            .ConfigureAwait(false);
        Assert.Equal("issued.pem: OK", result.Stdout.Trim());
    }

    private async Task CheckHealth()
    {
        var result = await Run(
            $"curl -fsS 'https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}/health'")
            .ConfigureAwait(false);
        Assert.Equal("Healthy", result.Stdout.Trim());
    }

    private async Task Enroll(
        string keyUsage = "digitalSignature", string extendedKeyUsage = "clientAuth", bool requestCa = false)
    {
        var keyOptions = _algorithm == "RSA" ? "-newkey rsa:2048" : "-newkey ec -pkeyopt ec_paramgen_curve:P-256";
        var constraints = requestCa ? " -addext 'basicConstraints=critical,CA:TRUE'" : "";
        var request = await Run(
            $"openssl req -new {keyOptions} -nodes -subj '/CN={IqAuthorityConfiguration.EstIdentity}'"
            + $" -addext 'subjectAltName=DNS:{IqAuthorityConfiguration.EstIdentity}'"
            + $" -addext 'keyUsage={keyUsage}' -addext 'extendedKeyUsage={extendedKeyUsage}'"
            + " -addext 'certificatePolicies=1.3.6.1.4.1.9999.2'"
            + constraints + " -keyout request.key -out request.csr"
            + " && openssl req -in request.csr -verify -noout -text").ConfigureAwait(false);
        Assert.Contains("Digital Signature", request.Stdout, StringComparison.Ordinal);
        Assert.Contains("TLS Web Client Authentication", request.Stdout, StringComparison.Ordinal);
        Assert.Contains("Policy: 1.3.6.1.4.1.9999.2", request.Stdout, StringComparison.Ordinal);
        if (requestCa)
        {
            Assert.Contains("CA:TRUE", request.Stdout, StringComparison.Ordinal);
        }

        if (requestCa)
        {
            var rejection = await RunEstClient($"-e -y '{Work}/request.csr'", "enrollment",
                "enrollment rv = 13 (EST_ERR_HTTP_BAD_REQ)", expectRejection: true).ConfigureAwait(false);
            _rejectionOutput = rejection.Stdout + rejection.Stderr;
            return;
        }

        await RunEstClient($"-e -y '{Work}/request.csr'", "enrollment",
            "enrollment rv = 0 (EST_ERR_NONE)").ConfigureAwait(false);
        await DecodePkcs7("enrollment/cert-0-0.pkcs7", "issued").ConfigureAwait(false);
        var leaf = await Run("openssl x509 -in issued.pem -noout -text").ConfigureAwait(false);
        Assert.Equal(["CA:FALSE"], Extension(leaf.Stdout, "X509v3 Basic Constraints", critical: true));
        await RunEstClient("-g", "authority", "Get CA Cert success").ConfigureAwait(false);
        await DecodePkcs7("authority/cacert-0-0.pkcs7", "ca").ConfigureAwait(false);
        await VerifyChain().ConfigureAwait(false);
        await Run("openssl pkey -in request.key -pubout -outform DER -out request.pub"
            + " && openssl x509 -in issued.pem -pubkey -noout"
            + " | openssl pkey -pubin -outform DER -out issued.pub"
            + " && cmp request.pub issued.pub").ConfigureAwait(false);
    }

    private async Task<ExecResult> RunEstClient(
        string options, string directory, string expectedMarker, bool expectRejection = false)
    {
        var result = await Run($"mkdir -p '{directory}'"
            + " && EST_OPENSSL_CACERT=/usr/local/share/ca-certificates/iq-tls-root.crt"
            + $" timeout 60s estclient -v -s '{IqAcmeEnvironment.ServerAlias}' -p {IqAcmeEnvironment.ServerPort}"
            + $" --path-seg '{_profile}' -w 20 -o '{Work}/{directory}'"
            + $" -u '{IqAuthorityConfiguration.EstIdentity}' -h '{_configuration.EstPassword}' {options} </dev/null")
            .ConfigureAwait(false);
        // libest's sample client can exit zero on protocol failure; require the expected outcome too.
        var output = result.Stdout + result.Stderr;
        Assert.Contains(expectedMarker, output, StringComparison.Ordinal);
        if (!expectRejection)
        {
            Assert.DoesNotContain("failed with code", output, StringComparison.OrdinalIgnoreCase);
        }
        Assert.DoesNotContain("server cert verification failed", output, StringComparison.OrdinalIgnoreCase);
        return result;
    }

    private Task<ExecResult> DecodePkcs7(string source, string name) => Run(
        $"openssl base64 -d -A -in '{source}' -out '{name}.p7'"
        + $" && openssl pkcs7 -inform DER -in '{name}.p7' -print_certs -out '{name}.pem'");

    private async Task<ExecResult> Run(string script)
    {
        var result = await _environment.ExecClientAsync(
            $"set -euo pipefail; mkdir -p '{Work}'; cd '{Work}'; {script}").ConfigureAwait(false);
        _state.LastExec = result;
        Assert.True(result.ExitCode == 0,
            $"Client command exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}");
        return result;
    }

    private static string[] Extension(string text, string name, bool critical = false)
    {
        var match = Regex.Match(text,
            $@"(?m)^            {Regex.Escape(name)}:{(critical ? " critical" : "(?: critical)?")}[ \t]*\r?\n((?:[ ]{{16,}}[^\r\n]*\r?\n)+)");
        Assert.True(match.Success, $"Missing or empty {(critical ? "critical " : "")}{name} extension in:\n{text}");
        return match.Groups[1].Value.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim()).Where(line => line.Length > 0).ToArray();
    }
}
