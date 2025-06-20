namespace OpenCertServer.Est.Tests;

using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Ca.Utils;
using Xunit;
using Xunit.Abstractions;

public sealed class EcDsaWebServerTests : WebServerTests
{
    private readonly ITestOutputHelper _output;

    public EcDsaWebServerTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task CanRequestEnroll()
    {
        using var ecdsa = ECDsa.Create();
        var certRequest = CreateCertificateRequest(ecdsa);
        var response = await Server.SendAsync(ctx =>
        {
            ctx.Request.Scheme = Uri.UriSchemeHttps;
            ctx.Request.Method = HttpMethod.Post.Method;
            ctx.Request.Path = "/.well-known/est/simpleenroll";
            ctx.Request.ContentType = "application/pkcs10-mime";
            ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(certRequest.ToPkcs10()));
#if NET8_0
            ctx.Connection.ClientCertificate = new X509Certificate2("test.pfx", (string?)null);
#else
            ctx.Connection.ClientCertificate = X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null);
#endif
        });

        _output.WriteLine(response.Response.StatusCode.ToString());
        Assert.Equal((int)HttpStatusCode.OK, response.Response.StatusCode);
    }

    [Fact]
    public async Task ReceiveValidCertificateOnEnroll()
    {
        using var ecdsa = ECDsa.Create();
        var certRequest = CreateCertificateRequest(ecdsa);
        var content = new StringContent(certRequest.ToPkcs10(), Encoding.UTF8, "application/pkcs10-mime");
        var client = new HttpClient(new TestMessageHandler(Server,
#if NET8_0
            new X509Certificate2("test.pfx", default(string?))
#else
            X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
#endif
        ));
        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri("https://localhost/.well-known/est/simpleenroll"),
            Version = HttpVersion.Version20,
            Content = content
        };

        var response = await client.SendAsync(request);

        var pkcs7 = await response.Content.ReadAsStringAsync();
        _output.WriteLine(pkcs7);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var s = new X509Certificate2Collection();
        s.ImportFromPem(pkcs7);
        var cert = s[^1].CopyWithPrivateKey(ecdsa);

        Assert.NotNull(cert.PublicKey);
    }

    [Fact]
    public async Task CanRequestReEnroll()
    {
        using var ecdsa = ECDsa.Create();
        var certRequest = CreateCertificateRequest(ecdsa);

        var certResponse = await Server.SendAsync(ctx =>
        {
            ctx.Request.Scheme = Uri.UriSchemeHttps;
            ctx.Request.Method = HttpMethod.Post.Method;
            ctx.Request.Path = "/.well-known/est/simpleenroll";
            ctx.Request.ContentType = "application/pkcs10-mime";
            ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(certRequest.ToPkcs10()));
#if NET8_0
            ctx.Connection.ClientCertificate = new X509Certificate2("test.pfx", (string?)null);
#else
            ctx.Connection.ClientCertificate = X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null);
#endif
        });

        Assert.Equal((int)HttpStatusCode.OK, certResponse.Response.StatusCode);

        using var reader = new StreamReader(certResponse.Response.Body);
        var responseString = await reader.ReadToEndAsync();
        var collection = new X509Certificate2Collection();
        collection.ImportFromPem(responseString);
        var cert = collection[^1].CopyWithPrivateKey(ecdsa);

        Assert.True(cert.HasPrivateKey);

        var response = await Server.SendAsync(ctx =>
        {
            ctx.Request.Scheme = Uri.UriSchemeHttps;
            ctx.Request.Method = HttpMethod.Post.Method;
            ctx.Request.Path = "/.well-known/est/simplereenroll";
            ctx.Connection.ClientCertificate = cert;
        });

        Assert.Equal((int)HttpStatusCode.OK, response.Response.StatusCode);
    }
}
