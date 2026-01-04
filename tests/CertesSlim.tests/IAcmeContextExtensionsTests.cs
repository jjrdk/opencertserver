using System;
using System.Threading.Tasks;
using CertesSlim.Acme.Resource;
using CertesSlim.Extensions;
using NSubstitute;
using Xunit;

namespace CertesSlim.Tests;

public class IAcmeContextExtensionsTests
{
    [Fact]
    public async Task CanGetTos()
    {
        var tosUri = new Uri("http://acme.d/tos");
        var ctxMock = Substitute.For<IAcmeContext>();
        ctxMock.GetDirectory()
            .Returns(new Directory(null, null, null, null, null, new DirectoryMeta(tosUri, null, null, null)));
        Assert.Equal(tosUri, await ctxMock.TermsOfService());

        ctxMock.GetDirectory()
            .Returns(new Directory(null, null, null, null, null, new DirectoryMeta(null, null, null, null)));
        Assert.Null(await ctxMock.TermsOfService());

        ctxMock.GetDirectory().Returns(new Directory(null, null, null, null, null, null));
        Assert.Null(await ctxMock.TermsOfService());
    }
}
