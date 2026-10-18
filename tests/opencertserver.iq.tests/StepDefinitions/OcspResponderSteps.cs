namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Text.RegularExpressions;
using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Checks the running OCSP responder with the Linux client's OpenSSL.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class OcspResponderSteps(
    ScenarioContext scenario, AcmeScenarioState state, CrlRevocationSteps revocation)
{
    public const string FeatureTitle = "The OCSP responder (RFC 6960) answers a Linux relying party";

    private readonly IqAcmeEnvironment _environment = scenario.Get<IqAcmeEnvironment>();
    private string _responseText = "";
    private string _verification = "";

    [Given("^a hardened OpenCertServer with a live certificate that the client enrolled$")]
    public Task EnrollLiveCertificate() => revocation.GivenOwnCertificate();

    [Given("^a certificate that has been revoked with a reason$")]
    public async Task EnrollAndRevokeCertificate()
    {
        await EnrollLiveCertificate().ConfigureAwait(false);
        await revocation.RevokeOwn("keyCompromise").ConfigureAwait(false);
    }

    [When("^the Linux client runs \"openssl ocsp\" to query the responder for that certificate$")]
    public Task QueryResponder() => Query("POST");

    [When("^the Linux client sends an OCSP request via (POST|GET) using \"openssl ocsp\"$")]
    public async Task QueryTransport(string transport)
    {
        // The outline has no Given: each row enrolls its own certificate.
        await EnrollLiveCertificate().ConfigureAwait(false);
        await Query(transport).ConfigureAwait(false);
    }

    private async Task Query(string transport)
    {
        var w = state.WorkDir;
        var url = $"https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}/ca/ocsp";
        var options = $"-issuer '{w}/rsa-ca.pem' -cert '{w}/target.pem'"
            + $" -CAfile '{w}/rsa-ca.pem' -no-CApath -no-CAstore"
            + $" -no_intern -verify_other '{w}/rsa-ca.pem' -validity_period 5 -status_age 300";

        ExecResult response;
        if (transport == "POST")
        {
            response = await Run($"openssl ocsp {options} -url '{url}' -timeout 15 -resp_text"
                + $" -respout '{w}/ocsp.der' > '{w}/ocsp.out' 2> '{w}/ocsp.err'"
                + $"; result=$?; cat '{w}/ocsp.out' '{w}/ocsp.err'; exit \"$result\"")
                .ConfigureAwait(false);
        }
        else
        {
            // OpenSSL has no GET switch; it still generates and verifies the OCSP messages.
            await Run($"openssl ocsp -issuer '{w}/rsa-ca.pem' -cert '{w}/target.pem'"
                + $" -no_nonce -reqout '{w}/ocsp-request.der'"
                + $" && request=$(openssl base64 -A -in '{w}/ocsp-request.der' | tr '+/' '-_' | tr -d '=')"
                + $" && curl -fsS --max-time 15 -H 'Accept: application/ocsp-response'"
                + $" -D '{w}/ocsp-headers' -o '{w}/ocsp.der' '{url}/'\"$request\"")
                .ConfigureAwait(false);
            var headers = await Run($"cat '{w}/ocsp-headers'").ConfigureAwait(false);
            Assert.Matches(@"(?im)^HTTP/\S+\s+200\b", headers.Stdout);
            Assert.Matches(@"(?im)^content-type:\s*application/ocsp-response\s*\r?$", headers.Stdout);
            response = await Run($"openssl ocsp {options} -no_nonce -respin '{w}/ocsp.der' -resp_text"
                + $" > '{w}/ocsp.out' 2> '{w}/ocsp.err'"
                + $"; result=$?; cat '{w}/ocsp.out' '{w}/ocsp.err'; exit \"$result\"")
                .ConfigureAwait(false);
        }

        _responseText = response.Stdout;
        _verification = response.Stdout + response.Stderr;
        Assert.Contains("OCSP Response Status: successful (0x0)", _responseText, StringComparison.Ordinal);
        AssertSignature();
    }

    [Then("^openssl reports the status as \"(good|revoked)\"$")]
    public void AssertStatus(string status)
    {
        Assert.Matches($@"(?m)^{Regex.Escape(state.WorkDir)}/target\.pem: {status}\r?$", _responseText);
        if (status == "revoked")
        {
            Assert.Contains("Revocation Reason: keyCompromise (0x1)", _responseText, StringComparison.Ordinal);
            Assert.Matches(@"Revocation Time:\s+\S", _responseText);
        }
    }

    [Then("^the response signature verifies against the responder key$")]
    public void AssertSignature() =>
        Assert.Contains("Response verify OK", _verification, StringComparison.Ordinal);

    [Then("^the responder returns a signed \"(good)\" response for a live certificate$")]
    public void AssertSignedStatus(string status)
    {
        AssertStatus(status);
        AssertSignature();
    }

    private async Task<ExecResult> Run(string script)
    {
        var result = await _environment.ExecClientAsync($"set -uo pipefail; {script}").ConfigureAwait(false);
        state.LastExec = result;
        Assert.True(result.ExitCode == 0,
            $"Linux OCSP command exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}");
        return result;
    }
}
