using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Est.Client;
using TechTalk.SpecFlow;
using Xunit;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

public partial class CertificateServerFeatures
{
    private EstClient _estClient = null!;
    private X509Certificate2Collection _certCollection = null!;

    [Given(@"an EST client")]
    public void GivenAnEstClient()
    {
        _estClient = new EstClient(new Uri("https://localhost"), _server.CreateHandler());
    }

    [When(@"I enroll with a valid JWT")]
    public async Task WhenIEnrollWithAValidJwt()
    {
        using var rsa = RSA.Create();
        _certCollection = await _estClient.Enroll(new X500DistinguishedName("cn=reimers.io"), rsa,
            X509KeyUsageFlags.KeyCertSign,
            new AuthenticationHeaderValue("Bearer", "valid-jwt"));
    }

    [Then(@"I should get a certificate")]
    public void ThenIShouldGetACertificate()
    {
        Assert.NotEmpty(_certCollection);
    }
}
