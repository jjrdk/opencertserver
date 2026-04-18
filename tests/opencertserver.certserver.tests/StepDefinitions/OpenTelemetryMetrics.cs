namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.Ocsp;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private MeterListener? _meterListener;
    private readonly Dictionary<string, long> _metricCounters = new();

    [Given("an OpenTelemetry meter listener")]
    public void GivenAnOpenTelemetryMeterListener()
    {
        _meterListener = new MeterListener();
        _meterListener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name.StartsWith("opencertserver.", StringComparison.OrdinalIgnoreCase))
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        _meterListener.SetMeasurementEventCallback<long>((instrument, measurement, _, _) =>
        {
            lock (_metricCounters)
            {
                _metricCounters.TryGetValue(instrument.Name, out var existing);
                _metricCounters[instrument.Name] = existing + measurement;
            }
        });
        _meterListener.Start();
    }

    [When("I fetch the CA certs over EST")]
    public async Task WhenIFetchTheCaCertsOverEst()
    {
        using var client = _server.CreateClient();
        var response = await client.GetAsync("/.well-known/est/rsa/cacerts").ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }

    [Then("the EST cacerts request counter should be greater than zero")]
    public void ThenTheEstCacertsRequestCounterShouldBeGreaterThanZero()
    {
        _meterListener?.RecordObservableInstruments();
        lock (_metricCounters)
        {
            Assert.True(
                _metricCounters.TryGetValue("opencertserver.est.cacerts.requests", out var count) && count > 0,
                $"Expected opencertserver.est.cacerts.requests > 0, actual: {(_metricCounters.TryGetValue("opencertserver.est.cacerts.requests", out var c) ? c : 0)}");
        }
    }

    [Then("the EST simpleenroll request counter should be greater than zero")]
    public void ThenTheEstSimpleenrollRequestCounterShouldBeGreaterThanZero()
    {
        _meterListener?.RecordObservableInstruments();
        lock (_metricCounters)
        {
            Assert.True(
                _metricCounters.TryGetValue("opencertserver.est.simpleenroll.requests", out var count) && count > 0,
                $"Expected opencertserver.est.simpleenroll.requests > 0, actual: {(_metricCounters.TryGetValue("opencertserver.est.simpleenroll.requests", out var c) ? c : 0)}");
        }
    }

    [When("I check the OCSP status of my certificate")]
    public async Task WhenICheckTheOcspStatusOfMyCertificate()
    {
        var issuerCert = await GetIssuerCertAsync().ConfigureAwait(false);
        var tbsRequest = new TbsRequest(requestList:
        [
            new Request(CertId.Create(_certCollection[0], issuerCert, HashAlgorithmName.SHA256))
        ]);
        var ocspRequest = new OcspRequest(tbsRequest);
        var ocspResponse = await GetOcspResponse(ocspRequest).ConfigureAwait(false);
        _scenarioContext["ocspResponse"] = ocspResponse;
    }

    [Then("the OCSP request counter should be greater than zero")]
    public void ThenTheOcspRequestCounterShouldBeGreaterThanZero()
    {
        _meterListener?.RecordObservableInstruments();
        lock (_metricCounters)
        {
            Assert.True(
                _metricCounters.TryGetValue("opencertserver.ocsp.request.requests", out var count) && count > 0,
                $"Expected opencertserver.ocsp.request.requests > 0, actual: {(_metricCounters.TryGetValue("opencertserver.ocsp.request.requests", out var c) ? c : 0)}");
        }
    }

    [When("I request the CRL")]
    public async Task WhenIRequestTheCrl()
    {
        using var client = _server.CreateClient();
        var response = await client.GetAsync("/ca/rsa/crl").ConfigureAwait(false);
        // CRL endpoint may return 200 or different codes; we capture it for the assertion
        _scenarioContext["crlStatusCode"] = (int)response.StatusCode;
    }

    [Then("the CRL request counter should be greater than zero")]
    public void ThenTheCrlRequestCounterShouldBeGreaterThanZero()
    {
        _meterListener?.RecordObservableInstruments();
        lock (_metricCounters)
        {
            Assert.True(
                _metricCounters.TryGetValue("opencertserver.crl.request.requests", out var count) && count > 0,
                $"Expected opencertserver.crl.request.requests > 0, actual: {(_metricCounters.TryGetValue("opencertserver.crl.request.requests", out var c) ? c : 0)}");
        }
    }

    [AfterScenario]
    public void DisposeMeterListener()
    {
        _meterListener?.Dispose();
        _meterListener = null;
    }
}

