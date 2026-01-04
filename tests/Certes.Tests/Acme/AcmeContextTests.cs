using System;
using System.Threading.Tasks;
using CertesSlim;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Xunit;
using static Certes.Helper;

namespace Certes.Acme;

public class AcmeContextTests
{
    [Fact]
    public async Task CanChangeKey()
    {
        var accountLoc = new Uri("https://acme.d/acct/1");
        var httpMock = Substitute.For<IAcmeHttpClient>();
        httpMock.Get<Directory>(Arg.Any<Uri>())
            .Returns(new AcmeHttpResponse<Directory>(accountLoc, MockDirectoryV2, null, null));
        httpMock.Post<Account, object>(MockDirectoryV2.NewAccount, Arg.Any<object>())
            .Returns(new AcmeHttpResponse<Account>(accountLoc, new Account
            {
                Status = AccountStatus.Valid
            }, null, null));
        httpMock.Post<Account, object>(MockDirectoryV2.KeyChange, Arg.Any<object>())
            .Returns(new AcmeHttpResponse<Account>(accountLoc, new Account { Status = AccountStatus.Valid }, null,
                null));

        var key = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        var ctx = new AcmeContext(
            WellKnownServers.LetsEncryptStagingV2,
            key,
            httpMock);

        var newKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        await ctx.ChangeKey(newKey);
        Assert.Equal(newKey.ToPem(), ctx.AccountKey.ToPem());

        ctx = new AcmeContext(
            WellKnownServers.LetsEncryptStagingV2,
            key,
            httpMock);
        await ctx.ChangeKey(null);
        Assert.NotEqual(key.ToPem(), ctx.AccountKey.ToPem());
    }

    [Fact]
    public void CanGetOrderByLocation()
    {
        var loc = new Uri("http://d.com/order/1");
        var ctx = new AcmeContext(WellKnownServers.LetsEncryptStagingV2);
        var order = ctx.Order(loc);

        Assert.Equal(loc, order.Location);
    }

    [Fact]
    public void CanGetAuthzByLocation()
    {
        var loc = new Uri("http://d.com/authz/1");
        var ctx = new AcmeContext(WellKnownServers.LetsEncryptStagingV2);
        var authz = ctx.Authorization(loc);

        Assert.Equal(loc, authz.Location);
    }

    [Fact]
    public async Task CanRevokeCertByPrivateKey()
    {
        var directoryUri = new Uri("http://acme.d/dict");
        var httpClientMock = Substitute.For<IAcmeHttpClient>();
        var certData = "cert"u8.ToArray();

        httpClientMock.Get<Directory>(directoryUri)
            .Returns(new AcmeHttpResponse<Directory>(directoryUri, Helper.MockDirectoryV2, default, default));
        httpClientMock.ConsumeNonce().Returns("nonce");

        httpClientMock.Post<string, object>(MockDirectoryV2.RevokeCert, Arg.Any<object>())
            .Returns(new AcmeHttpResponse<string>(default, default, default, default));

        var certKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);

        var client = new AcmeContext(directoryUri, http: httpClientMock);
        await client.RevokeCertificate(certData, RevocationReason.KeyCompromise, certKey);
    }
}
