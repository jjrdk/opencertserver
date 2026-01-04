using System;
using System.Linq;
using System.Threading.Tasks;
using CertesSlim;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using CertesSlim.Json;
using NSubstitute;
using Xunit;

namespace Certes.Acme;

public class OrderContextTests
{
    private Uri _location = new("http://acme.d/order/101");
    private IAcmeContext _contextMock = Substitute.For<IAcmeContext>();
    private IAcmeHttpClient _httpClientMock = Substitute.For<IAcmeHttpClient>();

    [Fact]
    public async Task CanLoadAuthorizations()
    {
        var order = new Order
        {
            Authorizations =
            [
                new Uri("http://acme.d/acct/1/authz/1"),
                new Uri("http://acme.d/acct/1/authz/2")
            ]
        };

        var expectedPayload = new JwsSigner(Helper.GetKeyV2())
            .Sign("", null, _location, "nonce");

        _contextMock.GetDirectory().Returns(Helper.MockDirectoryV2);
        _contextMock.AccountKey.Returns(Helper.GetKeyV2());
        _contextMock.BadNonceRetryCount.Returns(1);
        _contextMock.HttpClient.Returns(_httpClientMock);
        _contextMock.Sign(Arg.Any<object>(), Arg.Any<Uri>()).Returns(expectedPayload);
        _httpClientMock.Post<Order, JwsPayload>(_location, Arg.Any<JwsPayload>())
            .Returns(new AcmeHttpResponse<Order>(_location, order, default, default));

        var ctx = new OrderContext(_contextMock, _location);
        var authzs = await ctx.Authorizations();
        Assert.Equal(order.Authorizations, authzs.Select(a => a.Location));

        // check the context returns empty list instead of null
        _httpClientMock.Post<Order, JwsPayload>(_location, Arg.Any<JwsPayload>())
            .Returns(new AcmeHttpResponse<Order>(_location, new Order(), default, default));
        authzs = await ctx.Authorizations();
        Assert.Empty(authzs);
    }
}
