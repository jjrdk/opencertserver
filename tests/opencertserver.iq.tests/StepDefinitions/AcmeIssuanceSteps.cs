namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Globalization;
using System.Text.RegularExpressions;
using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

/// <summary>
/// Drives <c>acme.sh</c>, <c>certbot</c>, curl, openssl and jq inside the Debian client container against the running
/// OpenCertServer container. Every assertion is made on what the client tools observe.
/// </summary>
[Binding]
[Scope(Feature = FeatureTitle)]
[Scope(Feature = AuthorityInformationSteps.FeatureTitle)]
[Scope(Feature = LinuxServerDeploymentSteps.FeatureTitle)]
public sealed partial class AcmeIssuanceSteps
{
    public const string FeatureTitle = "RFC 8555 ACME issuance works for a Linux web-application client";

    private static readonly TimeSpan TosLeadTime = TimeSpan.FromSeconds(25);
    private readonly AcmeScenarioState _state;
    private readonly IqAcmeEnvironment _environment;

    public AcmeIssuanceSteps(ScenarioContext scenarioContext, AcmeScenarioState state)
    {
        _state = state;
        _environment = scenarioContext.Get<IqAcmeEnvironment>();
    }

    private string Server => $"https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}";

    private string AcmeHome => $"{_state.WorkDir}/acme";

    // acme.sh writes scratch files into --config-home before creating it, so the directory must exist.
    private string AcmeSh =>
        $"mkdir -p '{AcmeHome}' && acme.sh --server '{_environment.DirectoryUrl}' --config-home '{AcmeHome}'";

    private string CertbotHome => $"{_state.WorkDir}/certbot";

    // Per-scenario state and log directories keep certbot runs independent of each other and of /etc/letsencrypt.
    private string CertbotArgs =>
        $"--non-interactive --server '{_environment.DirectoryUrl}' --config-dir '{CertbotHome}/config'"
        + $" --work-dir '{CertbotHome}/work' --logs-dir '{CertbotHome}/logs'";

    private string CertbotNewAccountArgs => "--agree-tos --register-unsafely-without-email";

    [When("^the Linux client GETs \"(.*)\" with curl$")]
    public async Task WhenTheLinuxClientGetsWithCurl(string path)
    {
        var status = await Run(
                $"curl -sS -D '{_state.WorkDir}/headers' -o '{_state.WorkDir}/body' -w '%{{http_code}}' '{Server}{path}'")
            .ConfigureAwait(false);
        await CaptureResponse(status.Stdout, "headers", "body").ConfigureAwait(false);
    }

    [Then(@"^the response is HTTP (\d+)$")]
    public void ThenTheResponseIsHttp(int status) => Assert.Equal(status, _state.Status);

    [Then("^the directory JSON, filtered with \"jq\", lists (.*)$")]
    public async Task ThenTheDirectoryJsonListsFields(string fieldList)
    {
        var fields = QuotedValue().Matches(fieldList).Select(m => m.Groups[1].Value).ToArray();
        Assert.Equal(5, fields.Length);
        var filter = string.Join(" and ", fields.Select(f => $"(.{f} | type == \"string\" and startswith(\"https://\"))"));
        await Run($"jq -e '{filter}' '{_state.BodyPath}'").ConfigureAwait(false);
    }

    [Given("^a hardened OpenCertServer is reachable$")]
    public async Task GivenAHardenedOpenCertServerIsReachable()
    {
        // TLS is verified against the system trust store, which holds only the test TLS root.
        var health = await Run($"curl -fsS '{Server}/health'").ConfigureAwait(false);
        Assert.Equal("Healthy", health.Stdout.Trim());
    }

    [Given("^an ACME account exists on the server$")]
    public async Task GivenAnAcmeAccountExistsOnTheServer()
    {
        var result = await Run($"{AcmeSh} --register-account").ConfigureAwait(false);
        Assert.Contains("Registered", result.Stdout + result.Stderr, StringComparison.Ordinal);
        // acme.sh records the account location (the newAccount Location header) in its per-CA config.
        var accountUrl = await Run($"grep -rh '^ACCOUNT_URL=' '{AcmeHome}/ca'").ConfigureAwait(false);
        Assert.Matches(new Regex(@"ACCOUNT_URL='https://[^']+/account/[^']+'"), accountUrl.Stdout);
    }

    [Given("^a \"certbot\" ACME account exists on the server$")]
    public async Task GivenACertbotAccountExistsOnTheServer()
    {
        await WhenTheLinuxClientRegistersAnAccountViaCertbot().ConfigureAwait(false);
        await ThenTheClientExits0("certbot").ConfigureAwait(false);
        await ThenCertbotStoresTheAccountLocation().ConfigureAwait(false);
    }

    [When("^the Linux client registers an ACME account via \"certbot register\"$")]
    public async Task WhenTheLinuxClientRegistersAnAccountViaCertbot()
    {
        _state.LastExec = await _environment.ExecClientAsync(
                $"certbot register {CertbotNewAccountArgs} {CertbotArgs}")
            .ConfigureAwait(false);
    }

    [Then("^certbot stores the account location returned by the server$")]
    public async Task ThenCertbotStoresTheAccountLocation()
    {
        // certbot keeps the newAccount Location header as "uri" in the account's regr.json.
        var uri = await Run($"find '{CertbotHome}/config/accounts' -name regr.json -exec jq -r .uri {{}} +")
            .ConfigureAwait(false);
        Assert.Matches(new Regex(@"^https://[^/\s]+/account/\S+$"), uri.Stdout.Trim());
    }

    [When("^the Linux client runs \"(acme.sh|certbot)\" to issue \"(.*)\" via the \"(http-01|dns-01)\" challenge$")]
    public async Task WhenTheLinuxClientRunsAnAcmeClientToIssue(string client, string domain, string challenge)
    {
        _state.Domain = domain;
        _state.AcmeClient = client;
        string script;
        if (client == "acme.sh")
        {
            var mode = challenge == "http-01" ? "--standalone" : "--dns dns_iq --dnssleep 1";
            script = $"cd / && {AcmeSh} --issue -d '{domain}' {mode}";
        }
        else
        {
            var mode = challenge == "http-01"
                ? "--standalone"
                : "--manual --preferred-challenges dns"
                  + " --manual-auth-hook '/usr/local/bin/certbot-dns-iq.sh auth'"
                  + " --manual-cleanup-hook '/usr/local/bin/certbot-dns-iq.sh cleanup'";
            script = $"cd / && certbot certonly {mode} -d '{domain}' {CertbotNewAccountArgs} {CertbotArgs}";
        }

        _state.LastExec = await _environment.ExecClientAsync(script).ConfigureAwait(false);
    }

    public Task WhenTheLinuxClientRunsAcmeShToIssue(string domain, string challenge) =>
        WhenTheLinuxClientRunsAnAcmeClientToIssue("acme.sh", domain, challenge);

    public Task ThenAcmeShExits0() => ThenTheClientExits0("acme.sh");

    [Then("^(acme.sh|certbot) exits 0$")]
    public async Task ThenTheClientExits0(string client)
    {
        var exec = _state.LastExec!.Value;
        if (exec.ExitCode == 0)
        {
            return;
        }

        // certbot prints only a one-line summary; the protocol exchange and traceback are in its debug log.
        var log = client == "certbot"
            ? (await _environment.ExecClientAsync($"tail -n 150 '{CertbotHome}/logs/letsencrypt.log'")
                .ConfigureAwait(false)).Stdout
            : "";
        Assert.Fail($"{client} exited {exec.ExitCode}:\n{exec.Stdout}\n{exec.Stderr}\n{log}");
    }

    [Then("^the issued certificate chains to the published CA(?: with \"openssl verify\")?$")]
    public async Task ThenTheIssuedCertificateChainsToThePublishedCa()
    {
        var w = _state.WorkDir;
        await Run(
                $"curl -fsS '{Server}/.well-known/est/cacerts' | base64 -d"
                + $" | openssl pkcs7 -inform DER -print_certs -out '{w}/ca.pem'")
            .ConfigureAwait(false);
        var verify = await Run($"openssl verify -CAfile '{w}/ca.pem' '{CertificatePath()}'").ConfigureAwait(false);
        Assert.Contains(": OK", verify.Stdout, StringComparison.Ordinal);
        var subject = await Run($"openssl x509 -noout -ext subjectAltName -in '{CertificatePath()}'")
            .ConfigureAwait(false);
        Assert.Contains($"DNS:{_state.Domain}", subject.Stdout, StringComparison.Ordinal);
    }

    [Given("^EAB credentials \"(.*)\" and \"(.*)\" are supplied to the Linux client$")]
    public void GivenEabCredentialsAreSupplied(string kid, string hmac)
    {
        // The feature names the two inputs; the values are the key provisioned on the server for this run.
        Assert.Equal(("kid", "hmac"), (kid, hmac));
    }

    [When("^the Linux client creates an ACME account with EAB via \"(acme.sh|certbot)\"$")]
    public async Task WhenTheLinuxClientCreatesAnAcmeAccountWithEab(string client)
    {
        _state.AcmeClient = client;
        _state.LastExec = await _environment.ExecClientAsync(client == "acme.sh"
                ? $"cd / && {AcmeSh} --register-account --eab-kid '{IqAcmeEnvironment.EabKeyId}'"
                  + $" --eab-hmac-key '{_environment.EabHmacKey}' --debug 2"
                : $"certbot register {CertbotNewAccountArgs} --eab-kid '{IqAcmeEnvironment.CertbotEabKeyId}'"
                  + $" --eab-hmac-key '{_environment.CertbotEabHmacKey}' {CertbotArgs}")
            .ConfigureAwait(false);
    }

    [Then(@"^the account is created \(HTTP 200/201\) with a location$")]
    public async Task ThenTheAccountIsCreatedWithALocation()
    {
        var exec = _state.LastExec!.Value;
        var output = exec.Stdout + exec.Stderr;
        Assert.True(exec.ExitCode == 0, $"{_state.AcmeClient} exited {exec.ExitCode}:\n{output}");
        if (_state.AcmeClient == "certbot")
        {
            await ThenCertbotAccountWasBoundWithEab().ConfigureAwait(false);
            return;
        }

        // acme.sh --debug 2 logs the newAccount payload, the HTTP status and the response headers.
        Assert.Matches(new Regex(@"payload='\{[^']*""externalAccountBinding"":\{""protected"""), output);
        Assert.Matches(new Regex("code='20[01]'"), output);
        Assert.Matches(new Regex(@"(?im)^\s*location:\s*https://\S+/account/\S+"), output);
    }

    [Given("^an ACME account exists whose agreed TOS predates the server's \"AcmeServer:TOS:LastUpdate\"$")]
    public async Task GivenAnAccountWhoseTosAgreementPredatesTheLastUpdate()
    {
        // A dedicated server whose TOS "changes" shortly after start: the account agrees to the old terms
        // now, and the scenario continues once the server's clock has passed the update.
        var lastUpdate = DateTimeOffset.UtcNow.Add(TosLeadTime);
        _state.TosServer = await _environment.StartTosServerAsync(lastUpdate, CancellationToken.None)
            .ConfigureAwait(false);
        _state.DirectoryUrl = $"https://{IqAcmeEnvironment.TosServerAlias}:{IqAcmeEnvironment.ServerPort}/directory";

        await RawAcme("new-account").ConfigureAwait(false);
        Assert.Equal(201, _state.Status);
        var agreedAt = DateHeader(_state.Headers);
        Assert.True(agreedAt < lastUpdate, $"The account was created at {agreedAt:O}, after the TOS update {lastUpdate:O}.");

        var tosHost = $"https://{IqAcmeEnvironment.TosServerAlias}:{IqAcmeEnvironment.ServerPort}";
        while (true)
        {
            var date = await Run($"curl -fsS -o /dev/null -D - '{tosHost}/health' | tr -d '\\r'").ConfigureAwait(false);
            if (DateHeader(date.Stdout) > lastUpdate.AddSeconds(1))
            {
                break;
            }

            await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        }
    }

    [When("^the Linux client submits an order for a validated domain$")]
    [When("^the Linux client submits the order again$")]
    public Task WhenTheLinuxClientSubmitsAnOrder() => RawAcme("new-order acme.example.com");

    [Then(@"^the response is HTTP (\d+) ""(.*)""$")]
    public async Task ThenTheResponseIsHttpWithProblem(int status, string problem)
    {
        Assert.Equal(status, _state.Status);
        var type = await Run($"jq -r .type '{_state.BodyPath}'").ConfigureAwait(false);
        Assert.Equal($"urn:ietf:params:acme:error:{problem}", type.Stdout.Trim());
    }

    [Then("^the response carries a \"Link\" header to the terms-of-service$")]
    public void ThenTheResponseCarriesALinkHeaderToTheTermsOfService() =>
        Assert.Matches(
            new Regex(@"(?im)^link:\s*<https://[^>]+/terms-of-service>;\s*rel=""terms-of-service"""),
            _state.Headers);

    [When("^the Linux client agrees to the TOS via an account update$")]
    public async Task WhenTheLinuxClientAgreesToTheTos()
    {
        await RawAcme("agree-tos").ConfigureAwait(false);
        Assert.Equal(200, _state.Status);
    }

    [Then("^the order is accepted$")]
    public async Task ThenTheOrderIsAccepted()
    {
        Assert.Equal(201, _state.Status);
        Assert.Matches(new Regex(@"(?im)^location:\s*https://\S+"), _state.Headers);
        var status = await Run($"jq -r .status '{_state.BodyPath}'").ConfigureAwait(false);
        Assert.Equal("pending", status.Stdout.Trim());
    }

    [Given("^a Linux client holds a valid certificate issued by the server$")]
    public Task GivenALinuxClientHoldsAValidCertificate() =>
        GivenALinuxClientHoldsAValidCertificateFor("revoke.example.com", "acme.sh");

    [Given("^a Linux client holds a valid certificate for \"(.*)\" issued via \"(acme.sh|certbot)\"$")]
    public async Task GivenALinuxClientHoldsAValidCertificateFor(string domain, string client)
    {
        await _environment.AddDnsRecord(domain, "A", _environment.ClientIp).ConfigureAwait(false);
        if (client == "acme.sh")
        {
            await GivenAnAcmeAccountExistsOnTheServer().ConfigureAwait(false);
        }
        else
        {
            await GivenACertbotAccountExistsOnTheServer().ConfigureAwait(false);
        }

        await WhenTheLinuxClientRunsAnAcmeClientToIssue(client, domain, "http-01").ConfigureAwait(false);
        await ThenTheClientExits0(client).ConfigureAwait(false);
        await ThenTheIssuedCertificateChainsToThePublishedCa().ConfigureAwait(false);
        _state.Serial = await ReadSerial().ConfigureAwait(false);
    }

    [When("^the Linux client renews it via \"certbot renew --force-renewal\"$")]
    public async Task WhenTheLinuxClientRenewsItViaCertbot()
    {
        _state.LastExec = await _environment.ExecClientAsync(
                $"certbot renew --force-renewal --no-random-sleep-on-renew --cert-name '{_state.Domain}' {CertbotArgs}")
            .ConfigureAwait(false);
    }

    [Then("^the renewed certificate has a new serial and chains to the published CA$")]
    public async Task ThenTheRenewedCertificateHasANewSerialAndChains()
    {
        // certbot repoints live/<domain>/cert.pem at the new archive version on renewal.
        var renewedSerial = await ReadSerial().ConfigureAwait(false);
        Assert.NotEqual(_state.Serial, renewedSerial);
        await ThenTheIssuedCertificateChainsToThePublishedCa().ConfigureAwait(false);
    }

    [When("^the Linux client revokes it via \"certbot revoke\"$")]
    public async Task WhenTheLinuxClientRevokesItViaCertbot()
    {
        var revoke = await Run(
                $"certbot revoke --cert-path '{CertificatePath()}' --no-delete-after-revoke {CertbotArgs}")
            .ConfigureAwait(false);
        Assert.Contains("successfully revoked", revoke.Stdout + revoke.Stderr, StringComparison.OrdinalIgnoreCase);
    }

    [When("^the Linux client revokes it via \"acme.sh --revoke\"$")]
    public async Task WhenTheLinuxClientRevokesIt()
    {
        var revoke = await Run($"{AcmeSh} --revoke -d '{_state.Domain}' --ecc").ConfigureAwait(false);
        Assert.Contains("Successfully revoked", revoke.Stdout + revoke.Stderr, StringComparison.Ordinal);
    }

    [When("^the Linux client re-reads the server's CRL$")]
    public Task WhenTheLinuxClientReReadsTheCrl() =>
        Run($"curl -fsS -o '{_state.WorkDir}/ca.crl' '{Server}/ca/crl'");

    [Then("^the revoked serial appears in the CRL fetched with \"openssl crl\"$")]
    public async Task ThenTheRevokedSerialAppearsInTheCrl()
    {
        var crl = await Run($"openssl crl -inform DER -noout -text -in '{_state.WorkDir}/ca.crl'").ConfigureAwait(false);
        var serials = CrlSerial().Matches(crl.Stdout).Select(m => NormalizeSerial(m.Groups[1].Value)).ToList();
        Assert.Contains(_state.Serial!, serials);
    }

    [When("^the Linux client POSTs a request missing a \"nonce\" to an ACME endpoint$")]
    public Task WhenTheLinuxClientPostsARequestMissingANonce() => RawAcme("post-without-nonce newAccount");

    [Then("^the response content-type is \"(.*)\"$")]
    public void ThenTheResponseContentTypeIs(string contentType) =>
        Assert.Matches(new Regex($@"(?im)^content-type:\s*{Regex.Escape(contentType)}\b"), _state.Headers);

    [Then("^the body contains an \"(.*)\" and a \"(.*)\"$")]
    public Task ThenTheBodyContains(string first, string second) =>
        Run($"jq -e 'has(\"{first}\") and has(\"{second}\")' '{_state.BodyPath}'");

    private string CertificatePath() => _state.AcmeClient == "certbot"
        ? $"{CertbotHome}/config/live/{_state.Domain}/cert.pem"
        : $"{_state.WorkDir}/acme/{_state.Domain}_ecc/{_state.Domain}.cer";

    private async Task<string> ReadSerial()
    {
        var serial = await Run($"openssl x509 -noout -serial -in '{CertificatePath()}'").ConfigureAwait(false);
        return NormalizeSerial(serial.Stdout.Trim()["serial=".Length..]);
    }

    /// <summary>
    /// certbot's debug log (always written to --logs-dir) records each JWS payload and each response's
    /// status line and headers, which is where the EAB binding and the account location are observable.
    /// </summary>
    private async Task ThenCertbotAccountWasBoundWithEab()
    {
        var log = (await Run($"cat '{CertbotHome}/logs/letsencrypt.log'").ConfigureAwait(false)).Stdout;
        // The JWS payload is logged as a Python bytes literal, so its newlines appear as "\n" escapes.
        Assert.Matches(new Regex(@"""externalAccountBinding"":\s*\{(?:\\n|\s)*""protected"""), log);
        Assert.Matches(new Regex(@"(?m)^HTTP 20[01]\b"), log);
        Assert.Matches(new Regex(@"(?im)^location:\s*https://\S+/account/\S+"), log);
        await ThenCertbotStoresTheAccountLocation().ConfigureAwait(false);
    }

    private async Task RawAcme(string command)
    {
        var directory = _state.DirectoryUrl ?? _environment.DirectoryUrl;
        var raw = $"{_state.WorkDir}/raw";
        var result = await Run($"ACME_DIRECTORY='{directory}' acme-raw.sh '{raw}' {command}").ConfigureAwait(false);
        await CaptureResponse(result.Stdout, "raw/last.headers", "raw/last.body").ConfigureAwait(false);
    }

    private async Task CaptureResponse(string statusText, string headersFile, string bodyFile)
    {
        _state.Status = int.Parse(statusText.Trim().Split('\n')[^1], CultureInfo.InvariantCulture);
        _state.BodyPath = $"{_state.WorkDir}/{bodyFile}";
        var headers = await Run($"tr -d '\\r' < '{_state.WorkDir}/{headersFile}'").ConfigureAwait(false);
        _state.Headers = headers.Stdout;
    }

    /// <summary>Runs a script in the client container (inside the scenario's work directory) and requires success.</summary>
    private async Task<ExecResult> Run(string script)
    {
        var result = await _environment.ExecClientAsync($"mkdir -p '{_state.WorkDir}' && cd '{_state.WorkDir}' && {script}")
            .ConfigureAwait(false);
        _state.LastExec = result;
        Assert.True(
            result.ExitCode == 0,
            $"`{script}` exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}");
        return result;
    }

    private static DateTimeOffset DateHeader(string headers)
    {
        var match = Regex.Match(headers, @"(?im)^date:\s*(.+)$");
        Assert.True(match.Success, $"No Date header in:\n{headers}");
        return DateTimeOffset.ParseExact(
            match.Groups[1].Value.Trim(),
            "r",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal);
    }

    private static string NormalizeSerial(string serial) =>
        serial.Replace(":", "", StringComparison.Ordinal).Trim().TrimStart('0').ToUpperInvariant();

    [GeneratedRegex("\"([^\"]+)\"")]
    private static partial Regex QuotedValue();

    [GeneratedRegex(@"Serial Number:\s*([0-9A-Fa-f:]+)")]
    private static partial Regex CrlSerial();
}
