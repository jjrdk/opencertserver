namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using DotNet.Testcontainers.Containers;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

[Binding]
[Scope(Feature = FeatureTitle)]
public sealed class OpenTelemetrySteps(
    ScenarioContext scenario, FeatureContext feature, AcmeScenarioState state,
    OcspResponderSteps ocsp)
{
    public const string FeatureTitle = "OpenTelemetry signals are actually emitted after real traffic";

    private const string MetricsUrl = "http://telemetry:8889/metrics";
    private static readonly TimeSpan ExportTimeout = TimeSpan.FromSeconds(30);
    private readonly IqAcmeEnvironment _environment = scenario.Get<IqAcmeEnvironment>();
    private readonly IqAuthorityConfiguration _configuration = feature.Get<IqAuthorityConfiguration>();
    private readonly string _traceId = Guid.NewGuid().ToString("N");
    private readonly string _parentSpanId = Guid.NewGuid().ToString("N")[..16];
    private Dictionary<string, double> _baseline = [];
    private Dictionary<string, double> _scraped = [];
    private string[] _expectedCounters = [];

    private static string Server => $"https://{IqAcmeEnvironment.ServerAlias}:{IqAcmeEnvironment.ServerPort}";

    [Given("^a hardened OpenCertServer with OpenTelemetry (?:metrics|traces) exported$")]
    public async Task GivenTelemetry()
    {
        _baseline = await ReadMetrics().ConfigureAwait(false);
    }

    [When("^the Linux client calls \"(/\\.well-known/est/cacerts)\" and a live OCSP status$")]
    public async Task CallEndpoints(string path)
    {
        await Run($"curl -fsS --max-time 15 '{Server}{path}'"
            + $" | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out '{state.WorkDir}/cacerts.pem'"
            + $" && test -s '{state.WorkDir}/cacerts.pem'").ConfigureAwait(false);
        await ocsp.EnrollLiveCertificate().ConfigureAwait(false);
        await ocsp.QueryResponder().ConfigureAwait(false);
        ocsp.AssertStatus("good");
        _expectedCounters = ["opencertserver_est_cacerts_requests_total", "opencertserver_ocsp_request_requests_total"];
    }

    [When("^the Linux client performs one successful and one failing \"(simpleenroll)\"$")]
    public async Task EnrollBothOutcomes(string operation)
    {
        Assert.Equal("simpleenroll", operation);
        await Enroll().ConfigureAwait(false);
        var result = await Run($"curl -sS --max-time 15"
            + $" --user '{IqAuthorityConfiguration.EstIdentity}:{_configuration.EstPassword}'"
            + " -H 'Content-Type: application/pkcs10' --data-binary 'not-a-base64-csr!'"
            + $" -o '{state.WorkDir}/failure-body' -w '%{{http_code}}'"
            + $" '{Server}/.well-known/est/rsa/simpleenroll'").ConfigureAwait(false);
        Assert.Equal("400", result.Stdout.Trim());
        _expectedCounters =
        [
            "opencertserver_est_simpleenroll_requests_total",
            "opencertserver_est_simpleenroll_successes_total",
            "opencertserver_est_simpleenroll_failures_total"
        ];
    }

    [When("^that OpenTelemetry exporter is scraped$")]
    [When("^the exporter is scraped$")]
    public async Task Scrape()
    {
        var deadline = DateTimeOffset.UtcNow + ExportTimeout;
        do
        {
            _scraped = await ReadMetrics().ConfigureAwait(false);
            if (_expectedCounters.All(name => Delta(name) >= 1))
            {
                return;
            }

            await Task.Delay(500).ConfigureAwait(false);
        }
        while (DateTimeOffset.UtcNow < deadline);

        Assert.Fail($"Timed out waiting for exported counter increments: {string.Join(", ", _expectedCounters)}.\n"
            + $"Baseline: {JsonSerializer.Serialize(_baseline)}\nScraped: {JsonSerializer.Serialize(_scraped)}");
    }

    [Then("^the \"(opencertserver\\.est\\.cacerts|opencertserver\\.ocsp)\" counter is greater than 0$")]
    public void AssertCounter(string operation)
    {
        var name = operation == "opencertserver.ocsp"
            ? "opencertserver_ocsp_request_requests_total"
            : "opencertserver_est_cacerts_requests_total";
        Assert.True(Delta(name) >= 1, $"No new {name} measurement after Linux traffic.");
    }

    [Then("^a success outcome and a failure outcome are both reported for simpleenroll$")]
    public void AssertOutcomes()
    {
        Assert.True(Delta("opencertserver_est_simpleenroll_requests_total") >= 2);
        Assert.True(Delta("opencertserver_est_simpleenroll_successes_total") >= 1);
        Assert.True(Delta("opencertserver_est_simpleenroll_failures_total") >= 1);
    }

    [When("^the Linux client performs an EST enrollment$")]
    public async Task Enroll()
    {
        var w = state.WorkDir;
        await Run($"openssl req -new -newkey rsa:2048 -nodes"
            + $" -subj '/CN={IqAuthorityConfiguration.EstIdentity}'"
            + $" -keyout '{w}/enrollment.key' -outform DER -out '{w}/enrollment.csr'"
            + $" && openssl base64 -A -in '{w}/enrollment.csr' -out '{w}/enrollment.b64'"
            + $" && curl -fsS --max-time 15"
            + $" --user '{IqAuthorityConfiguration.EstIdentity}:{_configuration.EstPassword}'"
            + $" -H 'traceparent: 00-{_traceId}-{_parentSpanId}-01'"
            + " -H 'Content-Type: application/pkcs10' -H 'Accept: application/pkcs7-mime'"
            + $" --data-binary '@{w}/enrollment.b64' '{Server}/.well-known/est/rsa/simpleenroll'"
            + $" | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out '{w}/enrollment.pem'"
            + $" && curl -fsS --max-time 15 '{Server}/.well-known/est/rsa/cacerts'"
            + $" | openssl base64 -d -A | openssl pkcs7 -inform DER -print_certs -out '{w}/issuer.pem'"
            + $" && openssl verify -CAfile '{w}/issuer.pem' -purpose sslclient '{w}/enrollment.pem'"
            + $" && openssl x509 -in '{w}/enrollment.pem' -pubkey -noout | openssl pkey -pubin -outform DER > '{w}/cert.pub'"
            + $" && openssl pkey -in '{w}/enrollment.key' -pubout -outform DER > '{w}/key.pub'"
            + $" && cmp '{w}/cert.pub' '{w}/key.pub'").ConfigureAwait(false);
    }

    [Then("^an activity \\(\"operation\"\\) was emitted for the enrollment$")]
    public async Task AssertEnrollmentTrace()
    {
        var collector = feature.Get<IContainer>("TelemetryCollector");
        var deadline = DateTimeOffset.UtcNow + ExportTimeout;
        var exported = "";
        do
        {
            exported = System.Text.Encoding.UTF8.GetString(
                await collector.ReadFileAsync("/tmp/traces.json").ConfigureAwait(false));
            // The file exporter writes one OTLP JSON document per line; ignore an in-flight final line.
            foreach (var line in exported.Split('\n').SkipLast(1).Where(line => !string.IsNullOrWhiteSpace(line)))
            {
                using var document = JsonDocument.Parse(line);
                foreach (var resource in document.RootElement.GetProperty("resourceSpans").EnumerateArray())
                {
                    if (!resource.GetProperty("resource").GetProperty("attributes").EnumerateArray().Any(attribute =>
                            attribute.GetProperty("key").GetString() == "service.name"
                            && attribute.GetProperty("value").GetProperty("stringValue").GetString() == "opencertserver-iq"))
                    {
                        continue;
                    }

                    foreach (var scope in resource.GetProperty("scopeSpans").EnumerateArray()
                                 .Where(scope => scope.GetProperty("scope").GetProperty("name").GetString() == "opencertserver.est"))
                    {
                        foreach (var span in scope.GetProperty("spans").EnumerateArray())
                        {
                            if (span.GetProperty("traceId").GetString() != _traceId
                                || span.GetProperty("name").GetString() != "opencertserver.est.simpleenroll")
                            {
                                continue;
                            }

                            Assert.Matches("^[0-9a-f]{16}$", span.GetProperty("spanId").GetString()!);
                            Assert.NotEqual("0000000000000000", span.GetProperty("spanId").GetString());
                            Assert.Equal(1, span.GetProperty("status").GetProperty("code").GetInt32());
                            var start = ulong.Parse(span.GetProperty("startTimeUnixNano").GetString()!, CultureInfo.InvariantCulture);
                            var end = ulong.Parse(span.GetProperty("endTimeUnixNano").GetString()!, CultureInfo.InvariantCulture);
                            Assert.True(start > 0 && end > start, "Exported enrollment must have a positive duration.");
                            return;
                        }
                    }
                }
            }

            await Task.Delay(500).ConfigureAwait(false);
        }
        while (DateTimeOffset.UtcNow < deadline);

        Assert.Fail($"No successful enrollment span exported for trace {_traceId}.\n{exported}");
    }

    private double Delta(string name) => _scraped.GetValueOrDefault(name) - _baseline.GetValueOrDefault(name);

    private async Task<Dictionary<string, double>> ReadMetrics()
    {
        var result = await Run($"curl -fsS --max-time 5 '{MetricsUrl}'").ConfigureAwait(false);
        var counters = new Dictionary<string, double>(StringComparer.Ordinal);
        foreach (var line in result.Stdout.Split('\n'))
        {
            var match = Regex.Match(line, @"^(opencertserver_[a-z_]+_total)(?:\{[^}]*\})?\s+([0-9.eE+-]+)(?:\s|$)");
            if (match.Success)
            {
                var name = match.Groups[1].Value;
                Assert.Matches($@"(?m)^# TYPE {Regex.Escape(name)} counter\r?$", result.Stdout);
                counters[name] = counters.GetValueOrDefault(name)
                    + double.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture);
            }
        }

        return counters;
    }

    private async Task<ExecResult> Run(string script)
    {
        var result = await _environment.ExecClientAsync(
            $"set -euo pipefail; mkdir -p '{state.WorkDir}'; {script}").ConfigureAwait(false);
        state.LastExec = result;
        Assert.True(result.ExitCode == 0,
            $"Linux telemetry command exited {result.ExitCode}:\n{result.Stdout}\n{result.Stderr}");
        return result;
    }
}
