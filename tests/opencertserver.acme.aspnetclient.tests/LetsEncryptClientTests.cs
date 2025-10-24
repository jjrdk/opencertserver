namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Certes;
using Certificates;
using global::Certes;
using global::Certes.Acme;
using global::Certes.Acme.Resource;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence;
using Xunit;

public sealed class LetsEncryptClientTests
{
    private readonly IPersistenceService _persistenceService;
    private readonly IValidateCertificates _certificateValidator;
    private readonly IAcmeClientFactory _letsEncryptClientFactory;
    private readonly IAcmeClient _letsEncryptClient;
    private readonly CertificateProvider _sut;

    public LetsEncryptClientTests()
    {
        var persistenceService = Substitute.For<IPersistenceService>();

        var certificateValidator = Substitute.For<IValidateCertificates>();

        certificateValidator.IsCertificateValid(null).Returns(false);
        certificateValidator.IsCertificateValid(RefEq(InvalidCert)).Returns(false);
        certificateValidator.IsCertificateValid(RefEq(ValidCert)).Returns(true);

        var client = Substitute.For<IAcmeClient>();
        var factory = Substitute.For<IAcmeClientFactory>();

        factory.GetClient().Returns(Task.FromResult(client));

        var sut = new CertificateProvider(
            certificateValidator,
            persistenceService,
            factory,
            NullLogger<CertificateProvider>.Instance);

        _persistenceService = persistenceService;
        _certificateValidator = certificateValidator;
        _letsEncryptClientFactory = factory;
        _letsEncryptClient = client;

        _sut = sut;
    }

    private static X509Certificate2 ValidCert { get; } = SelfSignedCertificate.Make(
        DateTime.Now,
        DateTime.Now.AddDays(90));

    private static X509Certificate2 InvalidCert { get; } = SelfSignedCertificate.Make(
        DateTime.Now.AddDays(-180),
        DateTime.Now.AddDays(-90));

    [Fact]
    public async Task Should_TolerateNullInput()
    {
        _persistenceService.GetPersistedSiteCertificate()!
            .Returns(Task.FromResult(ValidCert));

        var output = await _sut.RenewCertificateIfNeeded("test");

        Assert.Equal(CertificateRenewalStatus.LoadedFromStore, output.Status);
        Assert.Equal(ValidCert, output.Certificate);
    }

    [Fact]
    public async Task OnValidMemoryCertificate_ShouldNotAttemptRenewal()
    {
        var input = ValidCert;
        var output = await _sut.RenewCertificateIfNeeded("test", input);

        Assert.Equal(CertificateRenewalStatus.Unchanged, output.Status);
        Assert.True(ReferenceEquals(input, output.Certificate));
    }

    [Fact]
    public async Task OnValidPersistedCertificate_ShouldNotAttemptRenewal()
    {
        var input = InvalidCert;
        var stored = ValidCert;

        _persistenceService.GetPersistedSiteCertificate()!.Returns(Task.FromResult(stored));

        var output = await _sut.RenewCertificateIfNeeded("test", input);

        Assert.Equal(CertificateRenewalStatus.LoadedFromStore, output.Status);
        Assert.Equal(stored, output.Certificate);
    }

    [Fact]
    public async Task OnNoValidCertificateAvailable_ShouldRenewCertificate()
    {
        // arrange

        _persistenceService.GetPersistedSiteCertificate()!.Returns(Task.FromResult(InvalidCert));

        var dtos = new[] { new ChallengeDto("ping", "pong", ["test.com"]) };
        var placedOrder = new PlacedOrder(dtos, Substitute.For<IOrderContext>(), []);

        _letsEncryptClient.PlaceOrder().Returns(Task.FromResult(placedOrder));
        _persistenceService.PersistChallenges(dtos).Returns(Task.CompletedTask);
        _persistenceService.DeleteChallenges(dtos).Returns(Task.CompletedTask);

        var newCertBytes = SelfSignedCertificate.Make(DateTime.Now, DateTime.Now.AddDays(90)).RawData;

        _letsEncryptClient.FinalizeOrder(placedOrder, "test")
            .Returns(Task.FromResult(
                X509CertificateLoader.LoadCertificate(newCertBytes)
            ));

        var newCertificate = X509CertificateLoader.LoadCertificate(newCertBytes);
        _persistenceService.PersistSiteCertificate(newCertificate).Returns(Task.CompletedTask);

        // act

        var output = await _sut.RenewCertificateIfNeeded("test", current: null);

        // assert

        Assert.Equal(CertificateRenewalStatus.Renewed, output.Status);
        Assert.Equivalent(newCertBytes, output.Certificate?.RawData);

        _certificateValidator.Received(1).IsCertificateValid(null);
        await _persistenceService.Received(1).GetPersistedSiteCertificate();
        _certificateValidator.Received(1).IsCertificateValid(InvalidCert);
        await _letsEncryptClient.Received(1).PlaceOrder();
        await _persistenceService.Received(1).PersistChallenges(dtos);
        await _persistenceService.Received(1).DeleteChallenges(dtos);
        await _persistenceService.Received(1).PersistChallenges(dtos);
        await _letsEncryptClient.Received(1).FinalizeOrder(placedOrder, "test");
        await _letsEncryptClientFactory.Received(1).GetClient();
    }

    [Fact]
    public async Task CheckAllChallengesValidated()
    {
        // arrange

        var pemCert = CertToPem(ValidCert);
        var certChain = new CertificateChain(pemCert);
        var readyOrder = new Order
        {
            Status = OrderStatus.Ready,
            Identifiers = [new Identifier { Value = "example.com" }]
        };
        var validOrder = new Order { Status = OrderStatus.Valid };
        var orderContext = Substitute.For<IOrderContext>();
        orderContext.Resource().Returns(readyOrder);
        orderContext.Finalize(null).ReturnsForAnyArgs(validOrder);
        orderContext.Download().Returns(certChain);

        var validChallenge = new Challenge { Status = ChallengeStatus.Valid };
        var pendingChallenge = new Challenge { Status = ChallengeStatus.Pending };
        var challenge1 = Substitute.For<IChallengeContext>();
        challenge1.Validate().Returns(validChallenge);
        challenge1.Resource().Returns(validChallenge);
        var challenge2 = Substitute.For<IChallengeContext>();
        challenge2.Validate().Returns(pendingChallenge);
        challenge2.Resource().Returns(validChallenge);

        var placedOrder = new PlacedOrder(null, orderContext, [challenge1, challenge2]);

        var options = new LetsEncryptOptions { CertificateSigningRequest = new CsrInfo() };

        var client = new AcmeClient(
            new AcmeContext(
                new Uri("http://localhost"),
                Substitute.For<IKey>()),
            options,
            NullLogger.Instance);

        // act

        var result = await client.FinalizeOrder(placedOrder, "");

        // assert
        var cert = X509CertificateLoader.LoadCertificate(result.RawData.AsSpan());
        Assert.Equal(CertToPem(cert), pemCert);
        await challenge1.Received().Validate();
        await challenge2.Received().Validate();
        await challenge2.Received().Resource();
    }

    private static string CertToPem(X509Certificate2 cert)
    {
        return string.Concat("-----BEGIN CERTIFICATE-----\n",
            Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks),
            "\n-----END CERTIFICATE-----");
    }

    private static T RefEq<T>(T it) => Arg.Is<T>(x => ReferenceEquals(x, it));
}
