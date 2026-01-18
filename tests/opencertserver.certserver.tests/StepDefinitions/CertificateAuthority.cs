using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TechTalk.SpecFlow;
using Xunit;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

public partial class CertificateServerFeatures
{
    private readonly ScenarioContext _scenarioContext;

    public CertificateServerFeatures(ScenarioContext scenarioContext)
    {
        _scenarioContext = scenarioContext;
    }

    [When("I check the initial CRL")]
    public async Task WhenICheckTheInitialCrl()
    {
        using var client = _server.CreateClient();
        var response = await client.GetAsync("ca/crl");
        response.EnsureSuccessStatusCode();
        var crl = await response.Content.ReadAsByteArrayAsync();
        _scenarioContext["crl"] = crl;
    }

    [Then("the CRL should be empty")]
    public void ThenTheCrlShouldBeEmpty()
    {
        var crl = (byte[])_scenarioContext["crl"];
        var builder = CertificateRevocationListBuilder.Load(crl, out _);
        var revokedEntries = typeof(CertificateRevocationListBuilder).GetField("_revoked", BindingFlags.Instance | BindingFlags.NonPublic);
        var entries = (System.Collections.ICollection?)revokedEntries?.GetValue(builder);
        Assert.NotNull(entries);
        Assert.Empty(entries);
    }

    [When("I revoke the certificate")]
    public async Task WhenIRevokeTheCertificate()
    {
        using var client = _server.CreateClient();
        var serialNumberString = _certCollection[0].GetSerialNumberString();
        var compromise = X509RevocationReason.KeyCompromise;
        var signature = _key.SignData(
            Encoding.UTF8.GetBytes(
                serialNumberString + compromise),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        var request = new HttpRequestMessage(
            HttpMethod.Delete,
            $"ca/revoke?sn={serialNumberString}&reason={compromise}&signature={Convert.ToBase64String(signature)}");
        request.Headers.Add("X-Client-Cert", Convert.ToBase64String(_certCollection[0].Export(X509ContentType.Cert)));
        request.Headers.Add("Authorization", "Bearer valid-jwt");
        var response = await client.SendAsync(request);
        response.EnsureSuccessStatusCode();
    }

    [Then("the certificate should be in the CRL")]
    public async Task ThenTheCertificateShouldBeInTheCrl()
    {
        using var client = _server.CreateClient();
        var response = await client.GetAsync("ca/crl");
        response.EnsureSuccessStatusCode();
        var crl = await response.Content.ReadAsByteArrayAsync();
        var builder = CertificateRevocationListBuilder.Load(crl, out _);
        Assert.True(builder.RemoveEntry(Encoding.UTF8.GetBytes(_certCollection[0].GetSerialNumberString())));
    }
}
