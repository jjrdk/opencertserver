using System.Threading.Tasks;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using CertesSlim.Extensions;
using NSubstitute;
using Xunit;

namespace CertesSlim.Tests;

public class IAuthorizationContextExtensionsTests
{
    [Fact]
    public async Task CanGetTlsAlpnChallenge()
    {
        var ctxMock =Substitute.For<IAuthorizationContext>();
        var challengeMock =Substitute.For<IChallengeContext>();

        challengeMock.Type.Returns(ChallengeTypes.Dns01);
        ctxMock.Challenges().Returns([challengeMock]);

        Assert.Null(await ctxMock.TlsAlpn());

        challengeMock.Type.Returns(ChallengeTypes.TlsAlpn01);
        ctxMock.Challenges().Returns([challengeMock]);

        Assert.Equal(challengeMock, await ctxMock.TlsAlpn());
    }
}