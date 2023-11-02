namespace OpenCertServer.Est.Tests;

using Microsoft.AspNetCore.Http;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Primitives;

public sealed class TestMessageHandler : HttpMessageHandler
{
    private readonly TestServer _server;
    private readonly X509Certificate2? _certificate;

    public TestMessageHandler(TestServer server, X509Certificate2? certificate = null)
    {
        _server = server;
        _certificate = certificate;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var response = await _server.SendAsync(
            async ctx =>
            {
                foreach (var (key, value) in request.Headers)
                {
                    ctx.Request.GetTypedHeaders().Set(key, new StringValues(value.ToArray()));
                }

                if (request.RequestUri != null)
                {
                    ctx.Request.Scheme = request.RequestUri.Scheme;
                }

                ctx.Request.Method = HttpMethod.Post.Method;
                ctx.Request.Path = request.RequestUri?.PathAndQuery;
                if (_certificate != null)
                {
                    ctx.Connection.ClientCertificate = _certificate;
                }

                if (request.Content != null)
                {
                    ctx.Request.Body =
                        await request.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                    ctx.Request.ContentType = request.Content.Headers.ContentType?.MediaType ?? "text/plain";
                }
            }, cancellationToken).ConfigureAwait(false);

        return new HttpResponseMessage
        {
            Content = new StreamContent(response.Response.Body),
            StatusCode = (HttpStatusCode)response.Response.StatusCode
        };
    }
}
