using System;
using System.Threading.Tasks;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using CertesSlim.Json;
using NSubstitute;
using NSubstitute.ReceivedExtensions;
using Xunit;

namespace CertesSlim.Tests.Acme;

public class AccountContextTests
{
    private Uri _location = new("http://acme.d/account/101");
    private IAcmeContext _contextMock = Substitute.For<IAcmeContext>();
    private IAcmeHttpClient _httpClientMock = Substitute.For<IAcmeHttpClient>();

    [Fact]
    public async Task CanDeactivateAccount()
    {
        var expectedPayload = new JwsPayload();
        var expectedAccount = new Account();

        _contextMock.GetDirectory().Returns(Task.FromResult(Helper.MockDirectoryV2));
        _contextMock.Sign(Arg.Any<object>(), _location).Returns(expectedPayload);
        _contextMock.HttpClient.Returns(_httpClientMock);
        _httpClientMock.Post<Account, JwsPayload>(_location, expectedPayload)
            .Returns(new AcmeHttpResponse<Account>(_location, expectedAccount, null, null));

        var instance = new AccountContext(_contextMock, _location);
        var account = await instance.Deactivate();

        await _httpClientMock.Received(Quantity.Exactly(1)).Post<Account, JwsPayload>(_location, expectedPayload);
        Assert.Equal(expectedAccount, account);
    }

    [Fact]
    public async Task CanLoadResource()
    {
        var expectedAccount = new Account();

        var expectedPayload = new JwsSigner(Helper.GetKeyV2())
            .Sign("", null, _location, "nonce");

        _contextMock.GetDirectory().Returns(Helper.MockDirectoryV2);
        _contextMock.AccountKey.Returns(Helper.GetKeyV2());
        _contextMock.HttpClient.Returns(_httpClientMock);
        _contextMock.Sign(Arg.Any<object>(), _location).Returns(expectedPayload);
        _httpClientMock.ConsumeNonce().Returns("nonce");
        _httpClientMock.Post<Account, JwsPayload>(_location, Arg.Any<JwsPayload>())
            .Returns(new AcmeHttpResponse<Account>(_location, expectedAccount, null, null));

        var instance = new AccountContext(_contextMock, _location);
        var account = await instance.Resource();

        Assert.Equal(expectedAccount, account);
    }

    [Fact]
    public async Task CanLoadOrderList()
    {
        var loc = new Uri("http://acme.d/acct/1/orders");
        var account = new Account
        {
            Orders = loc
        };
        var expectedPayload = new JwsSigner(Helper.GetKeyV2())
            .Sign(new Account(), null, _location, "nonce");

        _contextMock.GetDirectory().Returns(Helper.MockDirectoryV2);
        _contextMock.AccountKey.Returns(Helper.GetKeyV2());
        _contextMock.HttpClient.Returns(_httpClientMock);
        _contextMock.Sign(Arg.Any<object>(), _location).Returns(expectedPayload);
        _httpClientMock.ConsumeNonce().Returns("nonce");
        _httpClientMock.Post<Account, JwsPayload>(_location, Arg.Any<JwsPayload>()).Returns(new AcmeHttpResponse<Account>(_location, account, null, null));

        var ctx = new AccountContext(_contextMock, _location);
        var orders = await ctx.Orders();

        Assert.IsType<OrderListContext>(orders);
        Assert.Equal(loc, orders.Location);
    }
}
