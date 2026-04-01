namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Est.Client;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private RSA _key = null!;
    private EstClient _estClient = null!;
    private X509Certificate2Collection _certCollection = null!;

    [Given(@"an EST client")]
    public void GivenAnEstClient()
    {
        _estClient = new EstClient(new Uri("https://localhost"), messageHandler: _server.CreateHandler(),
            profileName: "rsa");
    }

    [When(@"I enroll with a valid JWT")]
    public async Task WhenIEnrollWithAValidJwt()
    {
        _key = RSA.Create();
        var (_, collection) = await _estClient.Enroll(new X500DistinguishedName("cn=test, ou=test"), _key,
            X509KeyUsageFlags.DigitalSignature,
            new AuthenticationHeaderValue("Bearer", "valid-jwt"));
        _certCollection = collection!;
    }

    [Then(@"I should get a certificate")]
    public void ThenIShouldGetACertificate()
    {
        Assert.NotEmpty(_certCollection);
    }

    [When(@"I get a certificate")]
    public void WhenIGetACertificate()
    {
        Assert.NotEmpty(_certCollection);
    }

    [When("I use the certificate to re-enroll without a valid JWT")]
    public async Task WhenIUseTheCertificateToReEnrollWithoutAValidJwt()
    {
        var (_, renewed) = await _estClient.ReEnroll(_key, _certCollection[0]);
        Assert.NotNull(renewed);
        Assert.NotEmpty(renewed);
        _certCollection = renewed;
        _key.Dispose();
    }

    [Then("I should get a new certificate")]
    public void ThenIShouldGetANewCertificate()
    {
        Assert.NotEmpty(_certCollection);
    }
}
