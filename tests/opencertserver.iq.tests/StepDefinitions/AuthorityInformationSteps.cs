namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Text.RegularExpressions;
using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Observes issued certificate extensions exclusively through the Linux client's openssl.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class AuthorityInformationSteps
{
    public const string FeatureTitle =
        "Issued certificates carry the CDP, AIA and OCSP extensions a hardened install embeds";

    private readonly AcmeScenarioState _state;
    private readonly IqAcmeEnvironment _environment;
    private readonly IqAuthorityConfiguration _configuration;
    private readonly AcmeIssuanceSteps _acme;
    private string _certificatePath = "";
    private string _certificateText = "";

    public AuthorityInformationSteps(
        ScenarioContext scenarioContext, FeatureContext featureContext, AcmeScenarioState state,
        AcmeIssuanceSteps acme)
    {
        _state = state;
        _environment = scenarioContext.Get<IqAcmeEnvironment>();
        _configuration = featureContext.Get<IqAuthorityConfiguration>();
        _acme = acme;
    }

    [Given("^an issued certificate is obtained through ACME for \"(.*)\"$")]
    public async Task ObtainAcmeCertificate(string domain)
    {
        await _environment.AddDnsRecord(domain, "A", _environment.ClientIp).ConfigureAwait(false);
        await _acme.GivenAnAcmeAccountExistsOnTheServer().ConfigureAwait(false);
        await _acme.WhenTheLinuxClientRunsAcmeShToIssue(domain, "http-01").ConfigureAwait(false);
        _acme.ThenAcmeShExits0();
        await _acme.ThenTheIssuedCertificateChainsToThePublishedCa().ConfigureAwait(false);
        _certificatePath = $"{_state.WorkDir}/acme/{domain}_ecc/{domain}.cer";
    }

    [When("^the Linux client inspects the certificate with \"openssl x509 -text\"$")]
    public async Task InspectCertificate()
    {
        var result = await Run($"openssl x509 -in '{_certificatePath}' -noout -text").ConfigureAwait(false);
        _certificateText = result.Stdout;
    }

    [Then("^the extension Authority Information Access lists the OCSP responder URL \"(.*)\"$")]
    public void AssertOcsp(string url) =>
        Assert.Equal([$"OCSP - URI:{url}", $"CA Issuers - URI:{IqAuthorityConfiguration.CaIssuersUrl}"],
            Extension(_certificateText, "Authority Information Access"));

    [Then("^the extension Authority Information Access caIssuers lists the URL \"(.*)\"$")]
    public void AssertCaIssuers(string url) =>
        Assert.Equal([$"OCSP - URI:{IqAuthorityConfiguration.OcspUrl}", $"CA Issuers - URI:{url}"],
            Extension(_certificateText, "Authority Information Access"));

    [Then("^the extension CRL Distribution Points lists the URL \"(.*)\"$")]
    public void AssertCrl(string url) =>
        Assert.Equal(["Full Name:", $"URI:{url}"], Extension(_certificateText, "X509v3 CRL Distribution Points"));

    [When("^the Linux client enrolls \"(.*)\" through EST's \"(simpleenroll)\" endpoint$")]
    public Task EnrollThroughEst(string domain, string endpoint) => Enroll(domain, endpoint);

    [Then("^the returned AIA and CRL distribution points match the ACME-issued certificate$")]
    public async Task CompareEstAndAcmeExtensions()
    {
        await InspectCertificate().ConfigureAwait(false);
        var estText = _certificateText;
        AssertOcsp(IqAuthorityConfiguration.OcspUrl);
        AssertCrl(IqAuthorityConfiguration.CrlUrl);

        // Each scenario obtains its own comparison certificate; no dependency on execution order.
        await ObtainAcmeCertificate("acme.example.com").ConfigureAwait(false);
        await InspectCertificate().ConfigureAwait(false);
        foreach (var name in new[] { "Authority Information Access", "X509v3 CRL Distribution Points" })
        {
            Assert.Equal(Extension(estText, name), Extension(_certificateText, name));
        }
    }

    [Given("^a hardened OpenCertServer with a fixed-extension profile configured$")]
    public Task GivenFixedExtensionProfile() => _acme.GivenAHardenedOpenCertServerIsReachable();

    [When("^the Linux client issues a certificate through that profile$")]
    public async Task IssueThroughProfile()
    {
        await Enroll(IqAuthorityConfiguration.EstIdentity, "rsa/simpleenroll").ConfigureAwait(false);
        await InspectCertificate().ConfigureAwait(false);
    }

    [Then("^the extended key usage extension equals the configured values$")]
    public void AssertExtendedKeyUsage() =>
        Assert.Equal([IqAuthorityConfiguration.ExtendedKeyUsages],
            Extension(_certificateText, "X509v3 Extended Key Usage"));

    [Then("^the certificate policies extension equals the configured values$")]
    public void AssertCertificatePolicies() =>
        Assert.Equal([$"Policy: {IqAuthorityConfiguration.PolicyOid}"],
            Extension(_certificateText, "X509v3 Certificate Policies"));

    private async Task Enroll(string domain, string endpoint)
    {
        Assert.Equal(IqAuthorityConfiguration.EstIdentity, domain);
        var w = _state.WorkDir;
        var server = $"https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}";
        // Request deliberately different EKU/policies so equality proves profile replacement, not echoing.
        await Run(
            $"openssl req -new -newkey rsa:2048 -nodes -subj '/CN={domain}'"
            + $" -addext 'subjectAltName=DNS:{domain}' -addext 'extendedKeyUsage=codeSigning'"
            + " -addext 'certificatePolicies=1.3.6.1.4.1.9999.2'"
            + $" -keyout '{w}/est.key' -outform DER -out '{w}/est.csr'"
            + $" && openssl base64 -A -in '{w}/est.csr' -out '{w}/est.csr.b64'"
            + $" && curl -fsS --user '{domain}:{_configuration.EstPassword}'"
            + " -H 'Content-Type: application/pkcs10' -H 'Accept: application/pkcs7-mime'"
            + $" --data-binary '@{w}/est.csr.b64' -o '{w}/est.p7.b64'"
            + $" '{server}/.well-known/est/{endpoint}'"
            + $" && openssl base64 -d -A -in '{w}/est.p7.b64' -out '{w}/est.p7'"
            + $" && openssl pkcs7 -inform DER -in '{w}/est.p7' -print_certs -out '{w}/est.pem'"
            + $" && curl -fsS '{server}/.well-known/est/cacerts' -o '{w}/ca.p7.b64'"
            + $" && openssl base64 -d -A -in '{w}/ca.p7.b64' -out '{w}/ca.p7'"
            + $" && openssl pkcs7 -inform DER -in '{w}/ca.p7' -print_certs -out '{w}/ca.pem'"
            + $" && openssl verify -CAfile '{w}/ca.pem' -verify_hostname '{domain}' '{w}/est.pem'")
            .ConfigureAwait(false);
        _certificatePath = $"{w}/est.pem";
    }

    private async Task<ExecResult> Run(string script)
    {
        var result = await _environment.ExecClientAsync(
                $"set -euo pipefail; mkdir -p '{_state.WorkDir}'; cd '{_state.WorkDir}'; {script}")
            .ConfigureAwait(false);
        _state.LastExec = result;
        Assert.True(result.ExitCode == 0,
            $"Client command exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}");
        return result;
    }

    private static string[] Extension(string text, string name)
    {
        var match = Regex.Match(text,
            $@"(?m)^            {Regex.Escape(name)}:(?: critical)?[ \t]*\r?\n((?:[ ]{{16,}}[^\r\n]*\r?\n)+)");
        Assert.True(match.Success, $"Missing or empty {name} extension in:\n{text}");
        return match.Groups[1].Value.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim()).Where(line => line.Length > 0).ToArray();
    }
}
