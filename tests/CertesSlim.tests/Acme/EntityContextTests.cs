using System;
using System.Threading.Tasks;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using CertesSlim.Json;
using NSubstitute;
using Xunit;

namespace CertesSlim.Tests.Acme;

public class EntityContextTests
{
    [Fact]
    public async Task CanLoadResource()
    {
        var location = new Uri("http://acme.d/acct/1");
        var acct = new Account();

        var expectedPayload = new JwsSigner(Helper.GetKeyV2())
            .Sign("", null, location, "nonce");

        var httpMock = Substitute.For<IAcmeHttpClient>();
        var ctxMock = Substitute.For<IAcmeContext>();
        ctxMock.HttpClient.Returns(httpMock);
        ctxMock.BadNonceRetryCount.Returns(1);
        ctxMock.Sign(Arg.Any<object>(), Arg.Any<Uri>()).Returns(expectedPayload);

        httpMock.Post<Account, JwsPayload>(location, Arg.Any<JwsPayload>())
            .Returns(new AcmeHttpResponse<Account>(location, acct, default, default));
        var ctx = new EntityContext<Account>(ctxMock, location);

        var res = await ctx.Resource();
        Assert.Equal(acct, res);

        location = new Uri("http://acme.d/acct/2");
        httpMock.Post<Account, JwsPayload>(location, Arg.Any<JwsPayload>())
            .Returns(new AcmeHttpResponse<Account>(location, default, default, new AcmeError { Detail = "err" }));
        ctx = new EntityContext<Account>(ctxMock, location);
        await Assert.ThrowsAsync<AcmeRequestException>(() => ctx.Resource());
    }
}
