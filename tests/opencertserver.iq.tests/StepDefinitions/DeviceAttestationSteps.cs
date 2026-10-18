namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Globalization;
using System.Text.Json;
using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>Qualifies device attestation through the Linux client and the deployed ACME server.</summary>
[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class DeviceAttestationSteps(ScenarioContext context, AcmeScenarioState state)
{
    public const string FeatureTitle = "The device-attest-01 challenge is advertised and fails closed";

    private IqAcmeEnvironment Environment => context.Get<IqAcmeEnvironment>();
    private string DirectoryUrl => state.DirectoryUrl ?? Environment.DirectoryUrl;
    private string RawDirectory => $"{state.WorkDir}/raw";
    private string _challengeUrl = "";
    private readonly List<string> _rejectedProofs = [];

    [When("^the Linux client GETs \"/directory\" with curl$")]
    public async Task GetDirectory()
    {
        var response = await Run(
            $"curl -sS --max-time 30 -D '{state.WorkDir}/headers' -o '{state.WorkDir}/directory.json'"
            + $" -w '%{{http_code}}' '{DirectoryUrl}'").ConfigureAwait(false);
        Assert.Equal("200", response.Stdout.Trim());
        state.BodyPath = $"{state.WorkDir}/directory.json";
    }

    [When("^the Linux client filters the meta block with \"jq\"$")]
    public Task FilterMeta() => Run($"jq -e '.meta | type == \"object\"' '{state.BodyPath}'");

    [Then("^\"meta.challengeTypesWithAdditionalContent\" contains \"device-attest-01\"$")]
    public Task DirectoryAdvertisesAttestation() => Run(
        $"jq -e '.meta.challengeTypesWithAdditionalContent | type == \"array\" and"
        + $" index(\"device-attest-01\") != null' '{state.BodyPath}'");

    [Given("a hardened OpenCertServer runs with the default empty IAttestationTrustProvider")]
    public async Task EmptyTrustProvider()
    {
        Assert.Null(state.TosServer);
        await GetDirectory().ConfigureAwait(false);
        await DirectoryAdvertisesAttestation().ConfigureAwait(false);
    }

    [Given("a hardened OpenCertServer runs with a non-empty set of trust roots")]
    public async Task ConfiguredTrustProvider()
    {
        var root = await Run($"python3 /usr/local/bin/device-attest.py '{state.WorkDir}' init")
            .ConfigureAwait(false);
        state.TosServer = await Environment.StartAttestationServerAsync(root.Stdout).ConfigureAwait(false);
        state.DirectoryUrl =
            $"https://{IqAcmeEnvironment.TosServerAlias}:{IqAcmeEnvironment.ServerPort}/directory";
        await GetDirectory().ConfigureAwait(false);
        await DirectoryAdvertisesAttestation().ConfigureAwait(false);
    }

    [When("the Linux client submits an order requiring device-attest-01")]
    public async Task SubmitOrder()
    {
        await Raw("new-account", 201).ConfigureAwait(false);
        await NewOrder().ConfigureAwait(false);
    }

    [Then("^the returned authorizations offer only \"http-01\" and \"dns-01\"$")]
    public async Task OnlyDomainChallenges()
    {
        var paths = await Run($"jq -er '.authorizations[]' '{state.WorkDir}/order.json'")
            .ConfigureAwait(false);
        var authorizations = paths.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.NotEmpty(authorizations);
        foreach (var url in authorizations)
        {
            await Raw($"post-as-get '{url}'", 200).ConfigureAwait(false);
            await Run(
                $"jq -e '.status == \"pending\" and .identifier.value == \"device.example.com\" and"
                + $" ([.challenges[].type] | sort == [\"dns-01\", \"http-01\"])' '{state.BodyPath}'")
                .ConfigureAwait(false);
        }
    }

    [When("the Linux client answers a device-attest-01 challenge with a malformed or empty proof")]
    public async Task AnswerWithBadProof()
    {
        await Raw("new-account", 201).ConfigureAwait(false);
        foreach (var mode in new[] { "empty", "malformed" })
        {
            await PrepareChallenge(mode).ConfigureAwait(false);
            await Raw($"answer '{_challengeUrl}' '{state.WorkDir}/answer.json'", 200).ConfigureAwait(false);
            await PollChallenge().ConfigureAwait(false);
            var snapshot = $"{state.WorkDir}/{mode}.json";
            await Run($"cp '{state.BodyPath}' '{snapshot}'").ConfigureAwait(false);
            _rejectedProofs.Add(snapshot);
        }
    }

    [Then("^the challenge is rejected with \"invalid_attestation\"$")]
    public async Task RejectInvalidAttestation()
    {
        Assert.Equal(2, _rejectedProofs.Count);
        foreach (var snapshot in _rejectedProofs)
        {
            await Run(
                $"jq -e '.status == \"invalid\" and .error.type == \"urn:ietf:params:acme:error:invalid_attestation\""
                + $" and .error.detail == \"Device attestation proof verification failed\""
                + $" and .validated == null' '{snapshot}'")
                .ConfigureAwait(false);
        }
    }

    [When("the Linux client submits a device-attest-01 answer twice with the same proof nonce")]
    public async Task ReplayProof()
    {
        await Raw("new-account", 201).ConfigureAwait(false);
        await PrepareChallenge("valid").ConfigureAwait(false);
        await Raw($"answer '{_challengeUrl}' '{state.WorkDir}/answer.json'", 200).ConfigureAwait(false);
        await PollChallenge().ConfigureAwait(false);
        await Run($"cp '{state.BodyPath}' '{state.WorkDir}/first.json'").ConfigureAwait(false);
        await Run(
            $"jq -e '.status == \"valid\" and .error == null and (.validated | type == \"string\")'"
            + $" '{state.WorkDir}/first.json'").ConfigureAwait(false);

        // The helper obtains a fresh outer JWS nonce, but reuses the exact attestation payload.
        await Raw($"answer '{_challengeUrl}' '{state.WorkDir}/answer.json'", 400).ConfigureAwait(false);
        await Run($"cp '{state.BodyPath}' '{state.WorkDir}/replay.json'").ConfigureAwait(false);
    }

    [Then("^the first answer validates and the second is rejected as \"replay_nonce\"$")]
    public async Task RejectReplayedNonce()
    {
        await Run(
            $"jq -e '.type == \"urn:ietf:params:acme:error:replay_nonce\" and .status == 400"
            + $" and (.detail | contains(\"consumed\"))' '{state.WorkDir}/replay.json'").ConfigureAwait(false);
        var headers = await Run($"cat '{RawDirectory}/last.headers'").ConfigureAwait(false);
        Assert.Contains("application/problem+json", headers.Stdout, StringComparison.Ordinal);
        await Raw($"post-as-get '{_challengeUrl}'", 200).ConfigureAwait(false);
        await Run(
            $"jq -e --slurpfile first '{state.WorkDir}/first.json'"
            + $" '.status == \"valid\" and .validated == $first[0].validated and .error == null'"
            + $" '{state.BodyPath}'").ConfigureAwait(false);
    }

    private async Task NewOrder()
    {
        await Raw("new-order device.example.com", 201).ConfigureAwait(false);
        await Run(
            $"jq -e '.status == \"pending\" and (.authorizations | length > 0)' '{state.BodyPath}'"
            + $" && cp '{state.BodyPath}' '{state.WorkDir}/order.json'").ConfigureAwait(false);
    }

    private async Task PrepareChallenge(string mode)
    {
        Assert.NotNull(state.TosServer);
        await NewOrder().ConfigureAwait(false);
        var authorization = await Run($"jq -er '.authorizations | select(length == 1) | .[0]' '{state.BodyPath}'")
            .ConfigureAwait(false);
        await Raw($"post-as-get '{authorization.Stdout.Trim()}'", 200).ConfigureAwait(false);
        await Run(
            $"jq -e '[.challenges[].type] | sort == [\"device-attest-01\", \"dns-01\", \"http-01\"]'"
            + $" '{state.BodyPath}'").ConfigureAwait(false);
        var challenge = await Run(
            $"jq -ce '.challenges[] | select(.type == \"device-attest-01\" and .status == \"pending\")'"
            + $" '{state.BodyPath}' | tee '{state.WorkDir}/challenge.json'").ConfigureAwait(false);
        using var document = JsonDocument.Parse(challenge.Stdout);
        _challengeUrl = document.RootElement.GetProperty("url").GetString()
            ?? throw new InvalidOperationException("Device challenge has no URL.");
        await Run(
            $"python3 /usr/local/bin/device-attest.py '{state.WorkDir}' answer"
            + $" '{state.WorkDir}/challenge.json' '{mode}'").ConfigureAwait(false);
    }

    private async Task PollChallenge()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        while (true)
        {
            deadline.Token.ThrowIfCancellationRequested();
            await Raw($"post-as-get '{_challengeUrl}'", 200).ConfigureAwait(false);
            var status = await Run($"jq -er .status '{state.BodyPath}'").ConfigureAwait(false);
            if (status.Stdout.Trim() is "valid" or "invalid")
            {
                return;
            }

            Assert.Contains(status.Stdout.Trim(), new[] { "pending", "processing" });
            await Task.Delay(TimeSpan.FromMilliseconds(250), deadline.Token).ConfigureAwait(false);
        }
    }

    private async Task Raw(string command, int expectedStatus)
    {
        var response = await Run(
            $"ACME_DIRECTORY='{DirectoryUrl}' acme-raw.sh '{RawDirectory}' {command}").ConfigureAwait(false);
        state.Status = int.Parse(response.Stdout.Trim(), CultureInfo.InvariantCulture);
        state.BodyPath = $"{RawDirectory}/last.body";
        if (state.Status != expectedStatus)
        {
            var body = await Run($"cat '{state.BodyPath}'").ConfigureAwait(false);
            Assert.Fail($"Expected HTTP {expectedStatus}, received {state.Status}: {body.Stdout}");
        }
    }

    private async Task<ExecResult> Run(string script)
    {
        var result = await Environment.ExecClientAsync(
            $"mkdir -p '{state.WorkDir}' && timeout 90 bash -euo pipefail -c {Quote(script)}")
            .ConfigureAwait(false);
        state.LastExec = result;
        var body = result.ExitCode == 0 ? "" : (await Environment.ExecClientAsync(
            $"if [ -f '{state.BodyPath}' ]; then cat '{state.BodyPath}'; fi").ConfigureAwait(false)).Stdout;
        Assert.True(result.ExitCode == 0,
            $"Linux client exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}\n{body}");
        return result;
    }

    private static string Quote(string value) => "'" + value.Replace("'", "'\"'\"'", StringComparison.Ordinal) + "'";
}
