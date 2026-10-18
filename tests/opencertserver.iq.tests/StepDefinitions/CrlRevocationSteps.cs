namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Globalization;
using System.Text.RegularExpressions;
using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Exercises CRL publication and signed revocation from the Linux client over verified TLS.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class CrlRevocationSteps
{
    public const string FeatureTitle = "CRL publication and revocation (RFC 5280) are usable from Linux";

    private readonly IqAcmeEnvironment _environment;
    private readonly IqAuthorityConfiguration _configuration;
    private readonly ScenarioContext _scenario;
    private readonly AcmeScenarioState _state;
    private string _caller = "target";
    private string? _token;
    private string _crlText = "";
    private string _certificateText = "";
    private string _reason = "keyCompromise";

    public CrlRevocationSteps(
        ScenarioContext scenario, FeatureContext feature, AcmeScenarioState state)
    {
        _scenario = scenario;
        _state = state;
        _environment = scenario.Get<IqAcmeEnvironment>();
        _configuration = feature.Get<IqAuthorityConfiguration>();
    }

    private static string Server => $"https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}";

    [When("^the Linux client GETs \"(/ca/crl)\" with curl$")]
    public Task GetCrl(string path) => Fetch(path);

    [Then("^the response content-type is \"(.*)\"$")]
    public void AssertContentType(string expected)
    {
        Assert.Equal(200, _state.Status);
        var header = Regex.Match(_state.Headers, @"(?im)^content-type:\s*([^\r\n;]+)");
        Assert.True(header.Success, $"Missing Content-Type in:\n{_state.Headers}");
        Assert.Equal(expected, header.Groups[1].Value.Trim());
    }

    [Then("^the body decodes as a CRL with \"openssl crl\"$")]
    public async Task DecodeCrl()
    {
        await DownloadIssuer("rsa").ConfigureAwait(false);
        var result = await Run(
            $"openssl crl -inform DER -in '{_state.BodyPath}' -noout -text -verify"
            + $" -CAfile '{_state.WorkDir}/rsa-ca.pem'").ConfigureAwait(false);
        Assert.Contains("verify OK", result.Stdout + result.Stderr, StringComparison.Ordinal);
        Assert.Contains("Certificate Revocation List (CRL)", result.Stdout, StringComparison.Ordinal);
        _crlText = result.Stdout;
    }

    [When("^the Linux client GETs a per-profile CRL with curl$")]
    public async Task GetProfileCrls()
    {
        foreach (var profile in new[] { "rsa", "ecdsa" })
        {
            await Fetch($"/ca/{profile}/crl").ConfigureAwait(false);
            AssertContentType("application/pkix-crl");
            await DownloadIssuer(profile).ConfigureAwait(false);
            var result = await Run(
                $"openssl crl -inform DER -in '{_state.BodyPath}' -noout -verify"
                + $" -CAfile '{_state.WorkDir}/{profile}-ca.pem'").ConfigureAwait(false);
            Assert.Contains("verify OK", result.Stdout + result.Stderr, StringComparison.Ordinal);
        }
    }

    [Given("^a hardened OpenCertServer with an authorized client certificate$")]
    public async Task GivenOwnCertificate()
    {
        await Enroll("target").ConfigureAwait(false);
        await AssertInitiallyUnrevoked().ConfigureAwait(false);
    }

    [Given("^a hardened OpenCertServer and a caller authenticated with the \"(ca_admin)\" role$")]
    public async Task GivenAdmin(string role)
    {
        Assert.Equal("ca_admin", role);
        await GivenDifferentCaller().ConfigureAwait(false);
        _token = _scenario.Get<string>("CrlAdminToken");
    }

    [Given("^a hardened OpenCertServer and a caller with neither matching thumbprint nor the \"(ca_admin)\" role$")]
    public async Task GivenNonAdmin(string role)
    {
        Assert.Equal("ca_admin", role);
        await GivenDifferentCaller().ConfigureAwait(false);
        _token = _scenario.Get<string>("CrlUserToken");
    }

    private async Task GivenDifferentCaller()
    {
        await Enroll("target").ConfigureAwait(false);
        await Enroll("caller").ConfigureAwait(false);
        _caller = "caller";
        var target = await Run($"openssl x509 -in '{_state.WorkDir}/target.pem' -noout -fingerprint -sha256")
            .ConfigureAwait(false);
        var caller = await Run($"openssl x509 -in '{_state.WorkDir}/caller.pem' -noout -fingerprint -sha256")
            .ConfigureAwait(false);
        Assert.NotEqual(target.Stdout.Trim(), caller.Stdout.Trim());
        await AssertInitiallyUnrevoked().ConfigureAwait(false);
    }

    [When("^the Linux client revokes its own certificate via \"DELETE /ca/revoke\" \\(reason \"(keyCompromise)\"\\)$")]
    public async Task RevokeOwn(string reason)
    {
        _reason = reason;
        await SubmitRevocation().ConfigureAwait(false);
        AssertAccepted();
    }

    [When("^the Linux client submits a revocation for any certificate via \"DELETE /ca/revoke\"$")]
    [When("^the Linux client submits a revocation via \"DELETE /ca/revoke\"$")]
    public async Task SubmitRevocation()
    {
        var w = _state.WorkDir;
        await ReadTargetSerial().ConfigureAwait(false);
        var authorization = _token is null ? "" : $" -H 'Authorization: Bearer {_token}'";
        var response = await Run(
            $"printf '%s' '{_state.Serial}{_reason}' | openssl dgst -sha256 -sign '{w}/{_caller}.key'"
            + $" -out '{w}/signature'"
            + $" && openssl base64 -A -in '{w}/signature' -out '{w}/signature.b64'"
            + $" && curl -sS --cert '{w}/{_caller}.pem' --key '{w}/{_caller}.key'{authorization}"
            + " -X DELETE -G"
            + $" --data-urlencode 'sn={_state.Serial}' --data-urlencode 'reason={_reason}'"
            + $" --data-urlencode 'signature@{w}/signature.b64'"
            + $" -D '{w}/headers' -o '{w}/body' -w '%{{http_code}}' '{Server}/ca/revoke'")
            .ConfigureAwait(false);
        await CaptureResponse(response.Stdout).ConfigureAwait(false);
    }

    [Then("^the revocation is accepted$")]
    public void AssertAccepted() => Assert.Equal(200, _state.Status);

    [Then(@"^the response is HTTP (\d+)$")]
    public async Task AssertStatus(int expected)
    {
        Assert.Equal(expected, _state.Status);
        if (expected == 403)
        {
            await RefreshCrl().ConfigureAwait(false);
            Assert.DoesNotContain(Serials(), serial => serial == NormalizeSerial(_state.Serial!));
            await Run(
                $"openssl verify -CAfile '{_state.WorkDir}/rsa-ca.pem' -crl_check"
                + $" -CRLfile '{_state.WorkDir}/crl.pem' '{_state.WorkDir}/target.pem'")
                .ConfigureAwait(false);
        }
    }

    [When("^the Linux client re-fetches the CRL with \"openssl crl\"$")]
    public Task RefreshCrl() => FetchAndDecodeCrl();

    [Then("^the revoked serial is present in the CRL$")]
    public async Task AssertRevoked()
    {
        Assert.Contains(NormalizeSerial(_state.Serial!), Serials());
        var entry = Regex.Matches(_crlText,
                @"(?s)Serial Number:\s*([0-9A-Fa-f]+)(.*?)(?=Serial Number:|Signature Algorithm:|\z)")
            .Single(match => NormalizeSerial(match.Groups[1].Value) == NormalizeSerial(_state.Serial!));
        Assert.Matches(@"X509v3 CRL Reason Code:\s+Key Compromise\b", entry.Groups[2].Value);

        var w = _state.WorkDir;
        var verification = await _environment.ExecClientAsync(
            $"openssl verify -CAfile '{w}/rsa-ca.pem' -crl_check -CRLfile '{w}/crl.pem' '{w}/target.pem'")
            .ConfigureAwait(false);
        _state.LastExec = verification;
        Assert.Equal(2, verification.ExitCode);
        Assert.Contains("certificate revoked", verification.Stdout + verification.Stderr, StringComparison.Ordinal);
    }

    [Then("^the revoked serial appears in the fetched CRL$")]
    public async Task FetchAndAssertRevoked()
    {
        await RefreshCrl().ConfigureAwait(false);
        await AssertRevoked().ConfigureAwait(false);
    }

    [When("^the Linux client inspects a freshly issued certificate with \"openssl x509 -text\"$")]
    public async Task InspectFreshCertificate()
    {
        await Enroll("target").ConfigureAwait(false);
        var result = await Run($"openssl x509 -in '{_state.WorkDir}/target.pem' -noout -text")
            .ConfigureAwait(false);
        _certificateText = result.Stdout;
    }

    [Then("^the certificate carries a CRL Distribution Point$")]
    public async Task AssertDistributionPoint()
    {
        var extension = Regex.Match(_certificateText,
            @"(?m)^            X509v3 CRL Distribution Points:\s*\r?\n((?:[ ]{16,}[^\r\n]*\r?\n)+)");
        Assert.True(extension.Success, $"Missing CRL Distribution Points in:\n{_certificateText}");
        Assert.Contains($"URI:{IqRevocationConfiguration.CrlUrl}",
            extension.Groups[1].Value.Split('\n').Select(line => line.Trim()));
        await Fetch(IqRevocationConfiguration.CrlUrl).ConfigureAwait(false);
        AssertContentType("application/pkix-crl");
        await DecodeCrl().ConfigureAwait(false);
    }

    private async Task AssertInitiallyUnrevoked()
    {
        await ReadTargetSerial().ConfigureAwait(false);
        await FetchAndDecodeCrl().ConfigureAwait(false);
        Assert.DoesNotContain(NormalizeSerial(_state.Serial!), Serials());
    }

    private async Task ReadTargetSerial()
    {
        var w = _state.WorkDir;
        var certificateSerial = await Run($"openssl x509 -in '{w}/target.pem' -noout -serial")
            .ConfigureAwait(false);
        var serial = certificateSerial.Stdout.Trim()["serial=".Length..];
        Assert.Matches("^(?:[0-9A-F]{2})+$", serial);
        // OpenSSL omits the DER INTEGER sign byte that .NET's GetSerialNumberString retains.
        _state.Serial = Convert.FromHexString(serial)[0] >= 0x80 ? $"00{serial}" : serial;
    }

    private async Task FetchAndDecodeCrl()
    {
        await Fetch("/ca/crl").ConfigureAwait(false);
        AssertContentType("application/pkix-crl");
        await DecodeCrl().ConfigureAwait(false);
        await Run(
            $"openssl crl -inform DER -in '{_state.BodyPath}' -out '{_state.WorkDir}/crl.pem'")
            .ConfigureAwait(false);
    }

    private string[] Serials() => Regex.Matches(_crlText, @"Serial Number:\s*([0-9A-Fa-f]+)")
        .Select(match => NormalizeSerial(match.Groups[1].Value)).ToArray();

    private static string NormalizeSerial(string serial) => serial.TrimStart('0').ToUpperInvariant();

    private async Task Enroll(string name)
    {
        var w = _state.WorkDir;
        await Run(
            $"openssl req -new -newkey rsa:2048 -nodes -subj '/CN={IqAuthorityConfiguration.EstIdentity}'"
            + $" -addext 'subjectAltName=DNS:{IqAuthorityConfiguration.EstIdentity}'"
            + $" -keyout '{w}/{name}.key' -outform DER -out '{w}/{name}.csr'"
            + $" && openssl base64 -A -in '{w}/{name}.csr' -out '{w}/{name}.csr.b64'"
            + $" && curl -fsS --user '{IqAuthorityConfiguration.EstIdentity}:{_configuration.EstPassword}'"
            + " -H 'Content-Type: application/pkcs10' -H 'Accept: application/pkcs7-mime'"
            + $" --data-binary '@{w}/{name}.csr.b64' '{Server}/.well-known/est/rsa/simpleenroll'"
            + $" | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out '{w}/{name}.pem'")
            .ConfigureAwait(false);
        await DownloadIssuer("rsa").ConfigureAwait(false);
        await Run($"openssl verify -CAfile '{w}/rsa-ca.pem' -purpose sslclient '{w}/{name}.pem'")
            .ConfigureAwait(false);
    }

    private Task<ExecResult> DownloadIssuer(string profile) => Run(
        $"curl -fsS '{Server}/.well-known/est/{profile}/cacerts'"
        + $" | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out '{_state.WorkDir}/{profile}-ca.pem'");

    private async Task Fetch(string path)
    {
        var w = _state.WorkDir;
        var url = new Uri(new Uri(Server), path);
        var result = await Run(
            $"curl -sS -D '{w}/headers' -o '{w}/body' -w '%{{http_code}}' '{url}'")
            .ConfigureAwait(false);
        await CaptureResponse(result.Stdout).ConfigureAwait(false);
    }

    private async Task CaptureResponse(string status)
    {
        _state.Status = int.Parse(status.Trim(), CultureInfo.InvariantCulture);
        _state.BodyPath = $"{_state.WorkDir}/body";
        var headers = await Run($"cat '{_state.WorkDir}/headers'").ConfigureAwait(false);
        _state.Headers = headers.Stdout;
    }

    private async Task<ExecResult> Run(string script)
    {
        var result = await _environment.ExecClientAsync(
            $"set -euo pipefail; mkdir -p '{_state.WorkDir}'; {script}").ConfigureAwait(false);
        _state.LastExec = result;
        Assert.True(result.ExitCode == 0,
            $"Linux command exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}");
        return result;
    }
}
