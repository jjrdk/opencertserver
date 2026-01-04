using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using CertesSlim.Extensions;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Xunit;

namespace CertesSlim.Tests;

public class IOrderContextExtensionsTests
{
    [Fact]
    public async Task CanGenerateCertificateWhenOrderReady()
    {
        var pem = await File.ReadAllTextAsync("./Data/cert-es256.pem");

        var orderCtxMock = Substitute.For<IOrderContext>();
        orderCtxMock.Download(null).Returns(new CertificateChain(pem));
        orderCtxMock.Resource().Returns(new Order
        {
            Identifiers =
            [
                new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
            ],
            Status = OrderStatus.Ready
        });
        orderCtxMock.Finalize(Arg.Any<byte[]>())
            .Returns(new Order
            {
                Identifiers =
                [
                    new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                ],
                Status = OrderStatus.Valid
            });

        var key = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        var certInfo = await orderCtxMock.Generate(new CsrInfo
        {
            CountryName = "C",
            CommonName = "www.certes.com"
        }, key, null);

        Assert.Equal(
            pem.Where(c => !char.IsWhiteSpace(c)),
            certInfo.Certificate.ExportCertificatePem().Where(c => !char.IsWhiteSpace(c)));

        var certInfoNoCn = await orderCtxMock.Generate(new CsrInfo
        {
            CountryName = "C"
        }, key, null);

        Assert.Equal(
            pem.Where(c => !char.IsWhiteSpace(c)),
            certInfoNoCn.Certificate.ExportCertificatePem().Where(c => !char.IsWhiteSpace(c)));
    }

    [Fact]
    public async Task CanGenerateCertificateWhenOrderPending()
    {
        var pem = await File.ReadAllTextAsync("./Data/cert-es256.pem");

        var orderCtxMock = Substitute.For<IOrderContext>();
        orderCtxMock.Download(null).Returns(new CertificateChain(pem));
        orderCtxMock.Resource().Returns(new Order
        {
            Identifiers =
            [
                new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
            ],
            Status = OrderStatus.Pending
        });
        orderCtxMock.Finalize(Arg.Any<byte[]>())
            .Returns(new Order
            {
                Identifiers =
                [
                    new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                ],
                Status = OrderStatus.Valid
            });

        var key = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        var certInfo = await orderCtxMock.Generate(new CsrInfo
        {
            CountryName = "C",
            CommonName = "www.certes.com"
        }, key, null);

        Assert.Equal(
            pem.Where(c => !char.IsWhiteSpace(c)),
            certInfo.Certificate.ExportCertificatePem().Where(c => !char.IsWhiteSpace(c)));

        var certInfoNoCn = await orderCtxMock.Generate(new CsrInfo
        {
            CountryName = "C"
        }, key, null);

        Assert.Equal(
            pem.Where(c => !char.IsWhiteSpace(c)),
            certInfoNoCn.Certificate.ExportCertificatePem().Where(c => !char.IsWhiteSpace(c)));
    }

    [Fact]
    public async Task CanGenerateCertificateWhenOrderProcessing()
    {
        var pem = await File.ReadAllTextAsync("./Data/cert-es256.pem");

        var orderCtxMock = Substitute.For<IOrderContext>();
        orderCtxMock.Download(null).Returns(new CertificateChain(pem));
        orderCtxMock.Resource()
            .Returns(
                new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Ready
                },
                new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Ready
                },
                new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Processing
                },
                new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Valid
                },
                new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Ready
                },
                new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Ready
                },
                new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Valid
                });
        orderCtxMock.Finalize(Arg.Any<byte[]>())
            .Returns(new Order
            {
                Identifiers =
                [
                    new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                ],
                Status = OrderStatus.Processing
            });

        var key = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        var certInfo = await orderCtxMock.Generate(new CsrInfo
        {
            CountryName = "C",
            CommonName = "www.certes.com"
        }, key, null, 5);

        Assert.Equal(
            pem.Where(c => !char.IsWhiteSpace(c)),
            certInfo.Certificate.ExportCertificatePem().Where(c => !char.IsWhiteSpace(c)));

        var certInfoNoCn = await orderCtxMock.Generate(new CsrInfo
        {
            CountryName = "C"
        }, key);

        Assert.Equal(
            pem.Where(c => !char.IsWhiteSpace(c)),
            certInfoNoCn.Certificate.ExportCertificatePem().Where(c => !char.IsWhiteSpace(c)));

        await orderCtxMock.Received(7).Resource();
    }


    [Fact]
    public async Task CanGenerateWithAlternateLink()
    {
        var defaultpem = await File.ReadAllTextAsync("./Data/defaultLeaf.pem");
        var alternatepem = await File.ReadAllTextAsync("./Data/alternateLeaf.pem");

        var accountLoc = new System.Uri("http://acme.d/account/101");
        var orderLoc = new System.Uri("http://acme.d/order/101");
        var finalizeLoc = new System.Uri("http://acme.d/order/101/finalize");
        var certDefaultLoc = new System.Uri("http://acme.d/order/101/cert/1234");
        var certAlternateLoc = new System.Uri("http://acme.d/order/101/cert/1234/1");

        var alternates = new[]
        {
            new { key = "alternate", value = certDefaultLoc },
            new { key = "alternate", value = certAlternateLoc }
        }.ToLookup(x => x.key, x => x.value);

        var httpClientMock = Substitute.For<IAcmeHttpClient>();

        httpClientMock.Post<string, object>(certDefaultLoc, Arg.Any<object>())
            .Returns(new AcmeHttpResponse<string>(accountLoc, defaultpem, alternates, null));

        httpClientMock.Post<string, object>(certAlternateLoc, Arg.Any<object>())
            .Returns(new AcmeHttpResponse<string>(accountLoc, alternatepem, alternates, null));

        httpClientMock.Post<Order, object>(finalizeLoc, Arg.Any<object>())
            .Returns(new AcmeHttpResponse<Order>(accountLoc, new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Valid
                },
                null,
                null));


        var acmeContextMock = Substitute.For<IAcmeContext>();
        acmeContextMock.HttpClient.Returns(httpClientMock);

        var orderCtxMock = Substitute.For<OrderContext>(acmeContextMock, orderLoc);
        orderCtxMock.Resource().Returns(new Order
        {
            Identifiers =
            [
                new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
            ],
            Certificate = certDefaultLoc,
            Finalize = finalizeLoc,
            Status = OrderStatus.Pending
        });

        var key = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        var certInfoDefaultRoot = await orderCtxMock.Generate(new CsrInfo
        {
            CountryName = "C",
            CommonName = "www.certes.com"
        }, key, null);

        Assert.Equal(
            defaultpem.Where(c => !char.IsWhiteSpace(c)),
            certInfoDefaultRoot.Certificate.ExportCertificatePem().Where(c => !char.IsWhiteSpace(c)));

        var certInfoAlternateRoot = await orderCtxMock.Generate(new CsrInfo
        {
            CountryName = "C",
            CommonName = "www.certes.com"
        }, key, "AlternateRoot");

        Assert.Equal(
            alternatepem.Where(c => !char.IsWhiteSpace(c)),
            certInfoAlternateRoot.Certificate.ExportCertificatePem().Where(c => !char.IsWhiteSpace(c)));

        var certInfoUnknownRoot = await orderCtxMock.Generate(new CsrInfo
        {
            CountryName = "C",
            CommonName = "www.certes.com"
        }, key, "UnknownRoot");

        Assert.Equal(
            defaultpem.Where(c => !char.IsWhiteSpace(c)),
            certInfoUnknownRoot.Certificate.ExportCertificatePem().Where(c => !char.IsWhiteSpace(c)));
    }

    [Fact]
    public async Task ThrowWhenOrderNotReady()
    {
        var orderCtxMock = Substitute.For<IOrderContext>();

        orderCtxMock.Resource().Returns(new Order
        {
            Identifiers =
            [
                new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
            ],
            Status = OrderStatus.Valid
        });

        var key = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        await Assert.ThrowsAsync<AcmeException>(() =>
            orderCtxMock.Generate(new CsrInfo
            {
                CountryName = "C",
                CommonName = "www.certes.com"
            }, key, null));
    }

    [Fact]
    public async Task ThrowWhenFinalizeFailed()
    {
        var pem = await File.ReadAllTextAsync("./Data/cert-es256.pem");

        var orderCtxMock = Substitute.For<IOrderContext>();
        orderCtxMock.Download(null).Returns(new CertificateChain(pem));
        orderCtxMock.Resource().Returns(new Order
        {
            Identifiers =
            [
                new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
            ],
            Status = OrderStatus.Pending
        });
        orderCtxMock.Finalize(Arg.Any<byte[]>())
            .Returns(new Order
            {
                Identifiers =
                [
                    new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                ],
                Status = OrderStatus.Invalid
            });

        var key = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        await Assert.ThrowsAsync<AcmeException>(() =>
            orderCtxMock.Generate(new CsrInfo
            {
                CountryName = "C",
                CommonName = "www.certes.com"
            }, key, null));
    }

    [Fact]
    public async Task ThrowWhenProcessintTooOften()
    {
        var pem = await File.ReadAllTextAsync("./Data/cert-es256.pem");

        var orderCtxMock = Substitute.For<IOrderContext>();
        orderCtxMock.Download(null).Returns(new CertificateChain(pem));
        orderCtxMock.Resource()
            .Returns(new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Ready
                },
                new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Ready
                },
                new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Processing
                },
                new Order
                {
                    Identifiers =
                    [
                        new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                    ],
                    Status = OrderStatus.Processing
                });

        orderCtxMock.Finalize(Arg.Any<byte[]>())
            .Returns(new Order
            {
                Identifiers =
                [
                    new Identifier { Value = "www.certes.com", Type = IdentifierType.Dns }
                ],
                Status = OrderStatus.Processing
            });

        var key = KeyFactory.NewKey(SecurityAlgorithms.RsaSha256);
        await Assert.ThrowsAsync<AcmeException>(() =>
            orderCtxMock.Generate(new CsrInfo
            {
                CountryName = "C",
                CommonName = "www.certes.com"
            }, key));
    }
}
