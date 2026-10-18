namespace OpenCertServer.Iq.Tests.StepDefinitions;

using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Observes CAA decisions through acme.sh and its actual HTTP responses.</summary>
[Scope(Feature = CaaFeatureTitle)]
public sealed partial class AcmeIssuanceSteps
{
    public const string CaaFeatureTitle =
        "CAA enforcement (RFC 8659 / RFC 8657) is observable through the ACME path";

    [Given("^a hardened OpenCertServer has CAA enforcement enabled(?: with \"AcmeServer:CAAIdentities\" set)?$")]
    public async Task GivenCaaEnforcementEnabled()
    {
        await GivenAHardenedOpenCertServerIsReachable().ConfigureAwait(false);
        await Run($"set -o pipefail; curl -fsS '{_environment.DirectoryUrl}'"
                  + $" | jq -e '.meta.caaIdentities == [\"{IqAcmeEnvironment.CaaIdentity}\"]'")
            .ConfigureAwait(false);
    }

    [Given("^a hardened OpenCertServer with \"AcmeServer:DisableCaaChecks\" set to true$")]
    public async Task GivenCaaChecksDisabled()
    {
        await GivenAHardenedOpenCertServerIsReachable().ConfigureAwait(false);
        // Without configured identities, the fail-closed default would refuse even a CAA-less domain.
        await Run($"set -o pipefail; curl -fsS '{_environment.DirectoryUrl}'"
                  + " | jq -e '(.meta.caaIdentities // []) | length == 0'")
            .ConfigureAwait(false);
    }

    [Given("^the domain \"(.*)\" has no CAA RRset that names this CA$")]
    public Task GivenAnotherCaaIssuer(string domain) =>
        _environment.AddDnsRecord(domain, "CAA", "0 issue \"other-ca.invalid\"");

    [Given("^the domain \"(.*)\" has a CAA RRset that names this CA$")]
    public Task GivenThisCaaIssuer(string domain) =>
        _environment.AddDnsRecord(domain, "CAA", $"0 issue \"{IqAcmeEnvironment.CaaIdentity}\"");

    [Given("^the domain \"(.*)\" has no CAA RRset$")]
    public Task GivenNoCaaRecords(string domain) =>
        Run("set -o pipefail; curl -fsS \"$IQ_DNS_API/records\""
            + $" | jq -e '((.[\"{domain}\"].CAA // []) | length) == 0"
            + " and ((.[\"example.com\"].CAA // []) | length) == 0'");

    [When("^the Linux client attempts to issue \"(.*)\" via \"acme.sh\"$")]
    public async Task AttemptCaaIssuance(string domain)
    {
        await _environment.AddDnsRecord(domain, "A", _environment.ClientIp).ConfigureAwait(false);
        await GivenAnAcmeAccountExistsOnTheServer().ConfigureAwait(false);
        _state.Domain = domain;
        _state.LastExec = await _environment.ExecClientAsync(
                $"cd / && {AcmeSh} --issue -d '{domain}' --standalone"
                + $" --debug 2 --log '{_state.WorkDir}/acme.log'")
            .ConfigureAwait(false);
    }

    [Then("^the order fails$")]
    public async Task AssertCaaOrderFailed()
    {
        var exec = _state.LastExec!.Value;
        Assert.True(exec.ExitCode != 0, $"acme.sh unexpectedly succeeded:\n{exec.Stdout}\n{exec.Stderr}");
        await Run($"test ! -s '{CertificatePath()}'").ConfigureAwait(false);
    }

    [Then("^the failure is a CAA error \\(\"caa\" type in the ACME challenge problem\\)$")]
    public async Task AssertCaaProblem()
    {
        var headers = await Run($"tr -d '\\r' < '{AcmeHome}/http.header'").ConfigureAwait(false);
        Assert.Matches(@"(?m)^HTTP/[\d.]+ 200\b", headers.Stdout);
        Assert.Matches(@"(?im)^content-type:\s*application/json\b", headers.Stdout);
        _state.BodyPath = $"{_state.WorkDir}/caa-problem.json";
        await Run($"set -o pipefail; sed -n \"s/^.*response='\\(.*\\)'$/\\1/p\" '{_state.WorkDir}/acme.log'"
                  + $" | tail -n 1 > '{_state.BodyPath}'"
                  + $" && test -s '{_state.BodyPath}'"
                  + $" && cat '{_state.BodyPath}'"
                  + " && jq -e '.status == \"invalid\""
                  + " and .type == \"http-01\" and .error.type == \"urn:ietf:params:acme:error:caa\"'"
                  + $" '{_state.BodyPath}'")
            .ConfigureAwait(false);
    }

    [Then("^the order succeeds and the issued certificate chains to the CA$")]
    public async Task AssertCaaIssuanceAndChain()
    {
        ThenAcmeShExits0();
        await ThenTheIssuedCertificateChainsToThePublishedCa().ConfigureAwait(false);
    }

    [Then("^the order succeeds$")]
    public Task AssertCaaIssuance() => AssertCaaIssuanceAndChain();
}
