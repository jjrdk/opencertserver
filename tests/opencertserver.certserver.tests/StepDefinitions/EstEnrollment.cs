namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Est.Client;
using Reqnroll;
using Xunit;
using Microsoft.AspNetCore.TestHost;

public partial class CertificateServerFeatures
{
    private RSA _key = null!;
    private EstClient _estClient = null!;
    private X509Certificate2Collection _certCollection = null!;

    [Given(@"an EST client")]
    public void GivenAnEstClient()
    {
        _estClient = new EstClient(new Uri("https://localhost"),
            options: null,
            messageHandler: _server.CreateHandler(),
            profileName: "rsa");
    }

    [When(@"I enroll with a valid JWT")]
    public async Task WhenIEnrollWithAValidJwt()
    {
        var estClient = _estClient;
        if (estClient is null)
        {
            GivenAnEstClient();
            estClient = _estClient;
        }

        _key = RSA.Create();
        var (_, collection) = await estClient.Enroll(new X500DistinguishedName("cn=test, ou=test"), _key,
            X509KeyUsageFlags.DigitalSignature,
            new AuthenticationHeaderValue("Bearer", "valid-jwt")).ConfigureAwait(false);
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
        using var certificate = _certCollection[0].CopyWithPrivateKey(_key);
        using var client = new EstClient(new Uri("https://localhost"), null, profileName: "rsa",
            messageHandler: new EnrollmentTlsHandler(_server, certificate));
        var (_, renewed) = await client.ReEnroll(_key, certificate).ConfigureAwait(false);
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

    private sealed class EnrollmentTlsHandler(TestServer server, X509Certificate2? certificate) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Assert.False(request.Headers.Contains("X-Client-Cert"));
            var context = await server.SendAsync(async context =>
            {
                context.Connection.ClientCertificate = certificate;
                context.Request.Scheme = "https";
                context.Request.Method = request.Method.Method;
                context.Request.Path = request.RequestUri!.AbsolutePath;
                context.Request.QueryString = new Microsoft.AspNetCore.Http.QueryString(request.RequestUri.Query);
                foreach (var header in request.Headers)
                {
                    context.Request.Headers[header.Key] = header.Value.ToArray();
                }

                if (request.Content != null)
                {
                    context.Request.Body = await request.Content.ReadAsStreamAsync(cancellationToken);
                    foreach (var header in request.Content.Headers)
                    {
                        context.Request.Headers[header.Key] = header.Value.ToArray();
                    }
                }
            }, cancellationToken);
            var content = new StreamContent(context.Response.Body);
            var response = new HttpResponseMessage((System.Net.HttpStatusCode)context.Response.StatusCode)
                { Content = content, RequestMessage = request };
            foreach (var header in context.Response.Headers)
            {
                if (!response.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                {
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                }
            }

            return response;
        }
    }
}
