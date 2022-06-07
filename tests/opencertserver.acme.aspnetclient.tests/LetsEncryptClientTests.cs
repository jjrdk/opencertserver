namespace OpenCertServer.Acme.AspNetClient.Tests
{
    using System;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Certes;
    using Certificates;
    using FluentAssertions;
    using FluentAssertions.Extensions;
    using global::Certes;
    using global::Certes.Acme;
    using global::Certes.Acme.Resource;
    using Microsoft.Extensions.Logging.Abstractions;
    using NSubstitute;
    using Persistence;
    using Xunit;

    public class LetsEncryptClientTests
    {
        private readonly IPersistenceService _persistenceService;
        private readonly ICertificateValidator _certificateValidator;
        private readonly IAcmeClientFactory _letsEncryptClientFactory;
        private readonly IAcmeClient _letsEncryptClient;
        private readonly CertificateProvider _sut;

        public LetsEncryptClientTests()
        {
            var persistenceService = Substitute.For<IPersistenceService>();

            var options = new LetsEncryptOptions
            {
                Domains = new[] { "test.com" },
                Email = "test@test.com",
                KeyAlgorithm = KeyAlgorithm.ES512,
                UseStaging = true,
            };

            var certificateValidator = Substitute.For<ICertificateValidator>();

            certificateValidator.IsCertificateValid(null).Returns(false);
            certificateValidator.IsCertificateValid(RefEq(InvalidCert)).Returns(false);
            certificateValidator.IsCertificateValid(RefEq(ValidCert)).Returns(true);

            var client = Substitute.For<IAcmeClient>();
            var factory = Substitute.For<IAcmeClientFactory>();

            factory.GetClient().Returns(Task.FromResult(client));

            var sut = new CertificateProvider(
                options,
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
            DateTime.Now.Subtract(180.Days()),
            DateTime.Now.Subtract(90.Days()));

        [Fact]
        public async Task Should_TolerateNullInput()
        {
            _persistenceService.GetPersistedSiteCertificate()!
                .Returns(Task.FromResult(ValidCert));

            var output = await _sut.RenewCertificateIfNeeded("test");

            output.Status.Should().Be(CertificateRenewalStatus.LoadedFromStore);
            Assert.Equal(ValidCert, output.Certificate);
        }

        [Fact]
        public async Task OnValidMemoryCertificate_ShouldNotAttemptRenewal()
        {
            var input = ValidCert;
            var output = await _sut.RenewCertificateIfNeeded("test", input);

            output.Status.Should().Be(CertificateRenewalStatus.Unchanged);
            ReferenceEquals(input, output.Certificate).Should().BeTrue();
        }

        [Fact]
        public async Task OnValidPersistedCertificate_ShouldNotAttemptRenewal()
        {
            var input = InvalidCert;
            var stored = ValidCert;

            _persistenceService.GetPersistedSiteCertificate()!.Returns(Task.FromResult(stored));

            var output = await _sut.RenewCertificateIfNeeded("test", input);

            output.Status.Should().Be(CertificateRenewalStatus.LoadedFromStore);
            Assert.Equal(stored, output.Certificate);
        }

        [Fact]
        public async Task OnNoValidCertificateAvailable_ShouldRenewCertificate()
        {
            // arrange

            _persistenceService.GetPersistedSiteCertificate()!.Returns(Task.FromResult(InvalidCert));

            var dtos = new[] { new ChallengeDto("ping", "pong", new[] { "test.com" }) };
            var placedOrder = new PlacedOrder(dtos, Substitute.For<IOrderContext>(), Array.Empty<IChallengeContext>());

            _letsEncryptClient.PlaceOrder(SeqEq(new[] { "test.com" })).Returns(Task.FromResult(placedOrder));
            _persistenceService.PersistChallenges(dtos).Returns(Task.CompletedTask);
            _persistenceService.DeleteChallenges(dtos).Returns(Task.CompletedTask);

            var newCertBytes = SelfSignedCertificate.Make(DateTime.Now, DateTime.Now.AddDays(90)).RawData;

            _letsEncryptClient.FinalizeOrder(placedOrder, "test").Returns(Task.FromResult(new X509Certificate2(newCertBytes)));

            var newCertificate = new X509Certificate2(newCertBytes);
            _persistenceService.PersistSiteCertificate(newCertificate).Returns(Task.CompletedTask);

            // act

            var output = await _sut.RenewCertificateIfNeeded("test", current: null);

            // assert

            output.Status.Should().Be(CertificateRenewalStatus.Renewed);
            output.Certificate?.RawData.Should().BeEquivalentTo(newCertBytes);

            _certificateValidator.Received(1).IsCertificateValid(null);
            await _persistenceService.Received(1).GetPersistedSiteCertificate();
            _certificateValidator.Received(1).IsCertificateValid(InvalidCert);
            await _letsEncryptClient.Received(1).PlaceOrder(SeqEq(new[] { "test.com" }));
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
                Identifiers = new[] { new Identifier { Value = "example.com" } }
            };
            var validOrder = new Order { Status = OrderStatus.Valid };
            var orderContext = Substitute.For<IOrderContext>();
            orderContext.Resource().Returns(readyOrder);
            orderContext.Finalize(default).ReturnsForAnyArgs(validOrder);
            orderContext.Download().Returns(certChain);

            var validChallenge = new Challenge { Status = ChallengeStatus.Valid };
            var pendingChallenge = new Challenge { Status = ChallengeStatus.Pending };
            var challenge1 = Substitute.For<IChallengeContext>();
            challenge1.Validate().Returns(validChallenge);
            challenge1.Resource().Returns(validChallenge);
            var challenge2 = Substitute.For<IChallengeContext>();
            challenge2.Validate().Returns(pendingChallenge);
            challenge2.Resource().Returns(validChallenge);

            var placedOrder = new PlacedOrder(null, orderContext, new[] { challenge1, challenge2 });

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

            var cert = new X509Certificate2(result.RawData);
            pemCert.Should().Be(CertToPem(cert));
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

        private static T[] SeqEq<T>(T[] xs) => Arg.Is<T[]>(ys => xs.SequenceEqual(ys));
        private static T RefEq<T>(T it) => Arg.Is<T>(x => ReferenceEquals(x, it));
    }
}