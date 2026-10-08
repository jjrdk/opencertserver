namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Ca.Server;
using Reqnroll;
using Xunit;

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
        var response = await client.GetAsync("ca/crl").ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var crl = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        _scenarioContext["crl"] = crl;
    }

    [Then("the CRL should be empty")]
    public void ThenTheCrlShouldBeEmpty()
    {
        var crl = (byte[])_scenarioContext["crl"];
        var builder = CertificateRevocationListBuilder.Load(crl, out _);
        var revokedEntries =
            typeof(CertificateRevocationListBuilder).GetField("_revoked",
                BindingFlags.Instance | BindingFlags.NonPublic);
        var entries = (System.Collections.ICollection?)revokedEntries?.GetValue(builder);
        Assert.NotNull(entries);
        Assert.Empty(entries);
    }

    [When("I revoke the certificate")]
    public async Task WhenIRevokeTheCertificate()
    {
        using var client = _server.CreateClient();
        var serialNumberString = _certCollection[0].GetSerialNumberString();
        const X509RevocationReason compromise = X509RevocationReason.KeyCompromise;
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
        var response = await client.SendAsync(request).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }

    [When("I try to revoke the certificate with a crafted certificate of the same serial")]
    public async Task WhenITryToRevokeTheCertificateWithACraftedSameSerialCertificate()
    {
        using var client = _server.CreateClient();
        var serialNumberHex = _certCollection[0].GetSerialNumberString();
        const X509RevocationReason compromise = X509RevocationReason.KeyCompromise;

        // Craft a self-signed certificate with the same serial number as the enrolled certificate.
        // Its thumbprint will differ from the stored cert so the store-lookup check must reject it.
        using var attackerKey = RSA.Create(2048);
        var req = new CertificateRequest(
            new X500DistinguishedName("CN=attacker"),
            attackerKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        var targetSerial = Convert.FromHexString(serialNumberHex);
        using var craftedCert = req.Create(
            req.SubjectName,
            X509SignatureGenerator.CreateForRSA(attackerKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1),
            targetSerial);

        var signature = attackerKey.SignData(
            Encoding.UTF8.GetBytes(serialNumberHex + compromise),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        var request = new HttpRequestMessage(
            HttpMethod.Delete,
            $"ca/revoke?sn={serialNumberHex}&reason={compromise}&signature={Convert.ToBase64String(signature)}");
        request.Headers.Add("X-Client-Cert", Convert.ToBase64String(craftedCert.Export(X509ContentType.Cert)));
        request.Headers.Add("Authorization", "Bearer non-admin");
        _scenarioContext["revocationResponse"] = await client.SendAsync(request).ConfigureAwait(false);
    }

    [When("I try to revoke the certificate with a different key")]
    public async Task WhenITryToRevokeTheCertificateWithADifferentKey()
    {
        var response = await SendRevocationWithDifferentKey("Bearer non-admin").ConfigureAwait(false);
        _scenarioContext["revocationResponse"] = response;
    }

    [When("an admin revokes the certificate with a different key")]
    public async Task WhenAnAdminRevokesTheCertificateWithADifferentKey()
    {
        var response = await SendRevocationWithDifferentKey("Bearer admin-token").ConfigureAwait(false);
        _scenarioContext["revocationResponse"] = response;
    }

    [Then("the revocation should be rejected with status Forbidden")]
    public void ThenTheRevocationShouldBeRejectedWithStatusForbidden()
    {
        var response = (HttpResponseMessage)_scenarioContext["revocationResponse"];
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Then("the certificate should be in the CRL")]
    public async Task ThenTheCertificateShouldBeInTheCrl()
    {
        using var client = _server.CreateClient();
        var response = await client.GetAsync("ca/crl").ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var crl = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        var builder = CertificateRevocationListBuilder.Load(crl, out _);
        Assert.True(builder.RemoveEntry(Convert.FromHexString(_certCollection[0].GetSerialNumberString())));
    }

    private async Task<HttpResponseMessage> SendRevocationWithDifferentKey(string authorizationHeader)
    {
        using var client = _server.CreateClient();
        var serialNumberString = _certCollection[0].GetSerialNumberString();
        const X509RevocationReason compromise = X509RevocationReason.KeyCompromise;

        // A key not associated with the certificate being revoked.
        using var attackerKey = RSA.Create(2048);
        var attackerCertRequest = new CertificateRequest(
            new X500DistinguishedName("CN=attacker"),
            attackerKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var attackerCert = attackerCertRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));

        var signature = attackerKey.SignData(
            Encoding.UTF8.GetBytes(serialNumberString + compromise),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        var request = new HttpRequestMessage(
            HttpMethod.Delete,
            $"ca/revoke?sn={serialNumberString}&reason={compromise}&signature={Convert.ToBase64String(signature)}");
        request.Headers.Add("X-Client-Cert",
            Convert.ToBase64String(attackerCert.Export(X509ContentType.Cert)));
        request.Headers.Add("Authorization", authorizationHeader);
        return await client.SendAsync(request).ConfigureAwait(false);
    }
}
