using System;
using System.Linq;
using System.Threading.Tasks;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using CertesSlim.Json;
using NSubstitute;
using Xunit;

namespace CertesSlim.Tests.Acme;

public class AuthorizationContextTests
{
    private Uri _location = new("http://acme.d/authz/101");
    private IAcmeContext _contextMock = Substitute.For<IAcmeContext>();
    private IAcmeHttpClient _httpClientMock = Substitute.For<IAcmeHttpClient>();

    [Fact]
    public async Task CanLoadChallenges()
    {
        var authz = new Authorization
        {
            Challenges =
            [
                new Challenge
                {
                    Url = new Uri("http://acme.d/c/1"),
                    Token = "token",
                    Type = "dns-01"
                },
                new Challenge
                {
                    Url = new Uri("http://acme.d/c/1"),
                    Token = "token",
                    Type = "http-01"
                }
            ]
        };

        var expectedPayload = new JwsSigner(Helper.GetKeyV2())
            .Sign("", null, _location, "nonce");

        _contextMock.GetDirectory().Returns(Helper.MockDirectoryV2);
        _contextMock.AccountKey.Returns(Helper.GetKeyV2());
        _contextMock.BadNonceRetryCount.Returns(1);
        _contextMock.Sign(Arg.Any<object>(), _location).Returns(expectedPayload);
        _contextMock.HttpClient.Returns(_httpClientMock);
        _httpClientMock.Post<Authorization, JwsPayload>(_location, Arg.Any<JwsPayload>())
            .Returns(new AcmeHttpResponse<Authorization>(_location, authz, default, default));

        var ctx = new AuthorizationContext(_contextMock, _location);
        var challenges = await ctx.Challenges();
        Assert.Equal(authz.Challenges.Select(c => c.Url), challenges.Select(a => a.Location));

        // check the context returns empty list instead of null
        _httpClientMock.Post<Authorization, JwsPayload>(_location, Arg.Any<JwsPayload>())
            .Returns(new AcmeHttpResponse<Authorization>(_location, new Authorization(), default, default));
        challenges = await ctx.Challenges();
        Assert.Empty(challenges);
    }
}
