namespace OpenCertServer.Est.Tests
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Ca.Utils;
    using Xunit;

    public class RsaWebServerTests : WebServerTests
    {
        [Fact]
        public async Task CanRequestEnroll()
        {
            using var rsa = RSA.Create(4096);
            var certRequest = CreateCertificateRequest(rsa);
            var content = new StringContent(certRequest.ToPkcs10(), Encoding.UTF8, "application/pkcs10-mime");
            var client = Server.CreateClient();
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri("https://localhost/.well-known/est/simpleenroll"),
                Version = HttpVersion.Version20,
                Content = content
            };
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes("test:test")));

            var response = await client.SendAsync(request).ConfigureAwait(false);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        [Fact]
        public async Task ReceiveValidCertificateOnEnroll()
        {
            using var rsa = RSA.Create(4096);
            var certRequest = CreateCertificateRequest(rsa);
            var content = new StringContent(certRequest.ToPkcs10(), Encoding.UTF8, "application/pkcs10-mime");
            var client = new HttpClient(new TestMessageHandler(Server, new X509Certificate2(X509Certificate.CreateFromCertFile("test.pfx"))));
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri("https://localhost/.well-known/est/simpleenroll"),
                Version = HttpVersion.Version20,
                Content = content
            };

            var response = await client.SendAsync(request).ConfigureAwait(false);
            var pkcs10 = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            var collection = new X509Certificate2Collection();
            collection.Import(pkcs10.FromPkcs7());
            var cert = collection[0].CopyWithPrivateKey(rsa);

            Assert.NotNull(cert.PublicKey);
        }

        [Fact]
        public async Task CanRequestReEnroll()
        {
            using var rsa = RSA.Create(4096);
            var certRequest = CreateCertificateRequest(rsa);

            var certResponse = await Server.SendAsync(
                ctx =>
                {
                    ctx.Request.Scheme = Uri.UriSchemeHttps;
                    ctx.Request.Method = HttpMethod.Post.Method;
                    ctx.Request.Path = "/.well-known/est/simpleenroll";
                    ctx.Request.ContentType = "application/pkcs10-mime";
                    ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(certRequest.ToPkcs10()));
                    ctx.Connection.ClientCertificate = new X509Certificate2(X509Certificate.CreateFromCertFile("test.pfx"));
                }).ConfigureAwait(false);
            using var reader = new StreamReader(certResponse.Response.Body);
            var responseString = await reader.ReadToEndAsync().ConfigureAwait(false);
            var certBytes = responseString.FromPkcs7();
            var collection = new X509Certificate2Collection();
            collection.Import(certBytes);
            var cert = collection[0].CopyWithPrivateKey(rsa);

            var response = await Server.SendAsync(
                    ctx =>
                    {
                        ctx.Request.Scheme = Uri.UriSchemeHttps;
                        ctx.Request.Method = HttpMethod.Post.Method;
                        ctx.Request.Path = "/.well-known/est/simplereenroll";
                        ctx.Request.ContentType = "application/pkcs10-mime";
                        ctx.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(certRequest.ToPkcs10()));
                        ctx.Connection.ClientCertificate = cert;
                    })
                .ConfigureAwait(false);

            Assert.Equal((int)HttpStatusCode.OK, response.Response.StatusCode);
        }
    }
}