using System;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Certes.Acme.Resource;
using Certes.Extensions;
using Certes.Json;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Xunit;
using static Certes.Helper;

namespace Certes.Acme;

public class AcmeHttpClientTests
{
    private class MockHttpMessageHandler : HttpMessageHandler
    {
        private readonly string _productVersion =
            typeof(AcmeHttpClient).GetTypeInfo().Assembly.GetName().Version!.ToString();

        public bool SendNonce { get; set; } = true;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            await Task.Yield();

            var isCertes = false;
            foreach (var header in request.Headers.UserAgent)
            {
                if (header.Product!.Name == "Certes" &&
                    header.Product.Version == _productVersion)
                {
                    isCertes = true;
                }
            }

            Assert.True(isCertes, "No user-agent header");

            if (request.RequestUri!.AbsoluteUri.EndsWith("directory"))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(MockDirectoryV2, CertesSerializerContext.Default.Directory),
                        Encoding.UTF8, "application/json"),
                };
            }
            else if (request.RequestUri.AbsoluteUri.EndsWith("newNonce"))
            {
                var resp = new HttpResponseMessage(HttpStatusCode.OK);
                if (SendNonce)
                {
                    resp.Headers.Add("Replay-Nonce", "nonce");
                }

                return resp;
            }

            return new HttpResponseMessage(HttpStatusCode.BadRequest);
        }
    }

    [Fact]
    public async Task ThrowWhenNoNonce()
    {
        var dirUri = new Uri("https://acme.d/directory");

        var httpHandler = new MockHttpMessageHandler
        {
            SendNonce = false
        };

        using (var http = new HttpClient(httpHandler))
        {
            var client = new AcmeHttpClient(dirUri, http);
            await Assert.ThrowsAsync<AcmeException>(() => client.ConsumeNonce());
        }
    }

    [Fact]
    public async Task RetryOnBadNonce()
    {
        var accountLoc = new Uri("https://acme.d/acct/1");
        var httpMock = Substitute.For<IAcmeHttpClient>();
        httpMock.Get<Directory>(Arg.Any<Uri>())
            .Returns(new AcmeHttpResponse<Directory>(accountLoc, MockDirectoryV2, null, null));
        httpMock.Post<Account, object>(MockDirectoryV2.NewAccount, Arg.Any<object>())
            .Returns(new AcmeHttpResponse<Account>(
                    accountLoc, null, null, new AcmeError
                    {
                        Status = HttpStatusCode.BadRequest,
                        Type = "urn:ietf:params:acme:error:badNonce"
                    }),
                new AcmeHttpResponse<Account>(
                    accountLoc, new Account
                    {
                        Status = AccountStatus.Valid
                    }, null, null));

        var key = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        var ctx = new AcmeContext(
            WellKnownServers.LetsEncryptStagingV2,
            key,
            httpMock);

        await ctx.NewAccount("", true);
        await httpMock.Received(2).Post<Account, object>(MockDirectoryV2.NewAccount, Arg.Any<object>());
    }

    [Fact]
    public async Task ThrowOnMultipleBadNonce()
    {
        var accountLoc = new Uri("https://acme.d/acct/1");
        var httpMock = Substitute.For<IAcmeHttpClient>();
        httpMock.Get<Directory>(Arg.Any<Uri>())
            .Returns(new AcmeHttpResponse<Directory>(accountLoc, MockDirectoryV2, null, null));
        httpMock.Post<Account, object>(MockDirectoryV2.NewAccount, Arg.Any<object>())
            .Returns(new AcmeHttpResponse<Account>(
                    accountLoc, null, null, new AcmeError
                    {
                        Status = HttpStatusCode.BadRequest,
                        Type = "urn:ietf:params:acme:error:badNonce"
                    }),
                new AcmeHttpResponse<Account>(
                    accountLoc, null, null, new AcmeError
                    {
                        Status = HttpStatusCode.BadRequest,
                        Type = "urn:ietf:params:acme:error:badNonce"
                    }),
                new AcmeHttpResponse<Account>(
                    accountLoc, new Account
                    {
                        Status = AccountStatus.Valid
                    }, null, null));

        var key = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        var ctx = new AcmeContext(WellKnownServers.LetsEncryptStagingV2, key, httpMock);

        await Assert.ThrowsAsync<AcmeRequestException>(() => ctx.NewAccount("", true));
        await SubstituteExtensions.Received(httpMock, 2)
            .Post<Account, object>(MockDirectoryV2.NewAccount, Arg.Any<object>());
    }
}