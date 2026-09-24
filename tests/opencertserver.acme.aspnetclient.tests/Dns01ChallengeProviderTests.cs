namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using OpenCertServer.Acme.AspNetClient.Certificates;
using Certes;
using CertesSlim.Acme;
using CertesSlim.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence;
using Xunit;

/// <summary>
/// Verifies that the renewal engine honours the configured challenge type: for DNS-01 it publishes
/// and removes the <c>_acme-challenge</c> TXT records through the <see cref="IDnsChallengeProvider"/>,
/// and that the http-01 path never touches the DNS provider.
/// </summary>
public sealed class Dns01ChallengeProviderTests
{
    private sealed class RecordingDnsProvider : IDnsChallengeProvider
    {
        public List<DnsChallengeRecord> Placed { get; } = [];
        public List<DnsChallengeRecord> Removed { get; } = [];

        public Task PlaceChallengesAsync(
            IReadOnlyList<DnsChallengeRecord> records,
            CancellationToken cancellationToken = default)
        {
            Placed.AddRange(records);
            return Task.CompletedTask;
        }

        public Task RemoveChallengesAsync(
            IReadOnlyList<DnsChallengeRecord> records,
            CancellationToken cancellationToken = default)
        {
            Removed.AddRange(records);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingDnsProviderOnPlace : IDnsChallengeProvider
    {
        public Task PlaceChallengesAsync(
            IReadOnlyList<DnsChallengeRecord> records,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new InvalidOperationException("dns publish failed");
        }

        public Task RemoveChallengesAsync(
            IReadOnlyList<DnsChallengeRecord> records,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }

    private readonly X509Certificate2 _validCert =
        SelfSignedCertificate.Make(DateTime.Now, DateTime.Now.AddDays(90));

    [Fact]
    public async Task Dns01_Publishes_Text_Records_Before_Finalize_And_Removes_After()
    {
        var dns = new RecordingDnsProvider();
        var persistence = Substitute.For<IPersistenceService>();
        var validator = Substitute.For<IValidateCertificates>();
        validator.IsCertificateValid(Arg.Any<X509Certificate2?>()).Returns(false);

        ChallengeDto[] challengeDtos = [
            new("base64-digest-value", "tok-base64", ["example.com"])
         ];
        var placedOrder = new PlacedOrder(challengeDtos, Substitute.For<IOrderContext>(), []);

        var client = FakeClient(
             placedOrder,
             ChallengeType.Dns01);
        var factory = Substitute.For<IAcmeClientFactory>();
        factory.GetClient().Returns(Task.FromResult(client));

        var provider = new CertificateProvider(
             validator,
             persistence,
             factory,
             dns,
             Dns01Options(),
             NullLogger<CertificateProvider>.Instance);

        var result = await provider.RenewCertificateIfNeeded(
            "pw",
            null,
            ["example.com"],
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(CertificateRenewalStatus.Renewed, result.Status);

        Assert.Single(dns.Placed);
        Assert.Equal("_acme-challenge.example.com", dns.Placed[0].Name);
        Assert.Equal("base64-digest-value", dns.Placed[0].Value);

        Assert.Single(dns.Removed);
        Assert.Equal("_acme-challenge.example.com", dns.Removed[0].Name);

        await client.Received(1).PlaceOrder(ChallengeType.Dns01, Arg.Any<string[]>());
        await client.DidNotReceive().PlaceOrder(ChallengeType.Http01, Arg.Any<string[]>());
    }

    [Fact]
    public async Task Http01_Never_Touches_The_Dns_Provider()
    {
        var dns = new RecordingDnsProvider();
        var persistence = Substitute.For<IPersistenceService>();
        var validator = Substitute.For<IValidateCertificates>();
        validator.IsCertificateValid(Arg.Any<X509Certificate2?>()).Returns(false);

        ChallengeDto[] challengeDtos = [
            new("token", "token-keyauthz", ["example.com"])
          ];
        var placedOrder = new PlacedOrder(challengeDtos, Substitute.For<IOrderContext>(), []);

        var client = FakeClient(
             placedOrder,
             ChallengeType.Http01);
        var factory = Substitute.For<IAcmeClientFactory>();
        factory.GetClient().Returns(Task.FromResult(client));

        var provider = new CertificateProvider(
             validator,
             persistence,
             factory,
             dns,
             Http01Options(),
             NullLogger<CertificateProvider>.Instance);

        var result = await provider.RenewCertificateIfNeeded(
            "pw",
            null,
            ["example.com"],
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(CertificateRenewalStatus.Renewed, result.Status);
        Assert.Empty(dns.Placed);
        Assert.Empty(dns.Removed);
        await client.Received(1).PlaceOrder(ChallengeType.Http01, Arg.Any<string[]>());
    }

    [Fact]
    public async Task Dns01_Wildcard_Derives_The_Bare_Host_Records()
    {
        var dns = new RecordingDnsProvider();
        var persistence = Substitute.For<IPersistenceService>();
        var validator = Substitute.For<IValidateCertificates>();
        validator.IsCertificateValid(Arg.Any<X509Certificate2?>()).Returns(false);

        ChallengeDto[] challengeDtos = [
            new("wildcard-digest", "tok-wildcard", ["*.example.com"])
           ];
        var placedOrder = new PlacedOrder(challengeDtos, Substitute.For<IOrderContext>(), []);

        var client = FakeClient(
             placedOrder,
             ChallengeType.Dns01);
        var factory = Substitute.For<IAcmeClientFactory>();
        factory.GetClient().Returns(Task.FromResult(client));

        var provider = new CertificateProvider(
             validator,
             persistence,
             factory,
             dns,
             Dns01Options(),
             NullLogger<CertificateProvider>.Instance);

        await provider.RenewCertificateIfNeeded(
            "pw",
            null,
            ["*.example.com"],
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.Single(dns.Placed);
        Assert.Equal("_acme-challenge.example.com", dns.Placed[0].Name);
    }

    [Fact]
    public async Task Dns01_Still_Deletes_Challenges_When_The_Record_Publish_Fails()
    {
        var failingProvider = new ThrowingDnsProviderOnPlace();
        var persistence = Substitute.For<IPersistenceService>();
        var validator = Substitute.For<IValidateCertificates>();
        validator.IsCertificateValid(Arg.Any<X509Certificate2?>()).Returns(false);

        ChallengeDto[] challengeDtos = [
            new("digest", "tok", ["example.com"])
            ];
        var placedOrder = new PlacedOrder(challengeDtos, Substitute.For<IOrderContext>(), []);

        var client = Substitute.For<IAcmeClient>();
        client.PlaceOrder(ChallengeType.Dns01, Arg.Any<string[]>())
                 .Returns(Task.FromResult(placedOrder));
        var factory = Substitute.For<IAcmeClientFactory>();
        factory.GetClient().Returns(Task.FromResult(client));

        var provider = new CertificateProvider(
             validator,
             persistence,
             factory,
             failingProvider,
             Dns01Options(),
             NullLogger<CertificateProvider>.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.RenewCertificateIfNeeded(
                "pw",
                null,
                ["example.com"],
                cancellationToken: TestContext.Current.CancellationToken));

        await persistence.Received(1).DeleteChallenges(challengeDtos);
    }

    private IAcmeClient FakeClient(PlacedOrder placedOrder, ChallengeType expectedType)
    {
        var client = Substitute.For<IAcmeClient>();
        client.PlaceOrder(expectedType, Arg.Any<string[]>())
                  .Returns(Task.FromResult(placedOrder));
        var collection = new X509Certificate2Collection { _validCert };
        client.FinalizeOrder(placedOrder, Arg.Any<string>(), Arg.Any<string?>())
                  .Returns(Task.FromResult((_validCert, string.Empty, collection)));
        return client;
    }

    private static TestOptions Dns01Options()
            => new()
            {
                AccountPassword = "pw",
                Email = "test@example.com",
                CertificateSigningRequest = new CsrInfo(),
                ChallengeType = ChallengeType.Dns01
            };

    private static TestOptions Http01Options()
             => new()
             {
                 AccountPassword = "pw",
                 Email = "test@example.com",
                 CertificateSigningRequest = new CsrInfo(),
                 ChallengeType = ChallengeType.Http01
             };

    private sealed class TestOptions : AcmeOptions
    {
        public override Uri AcmeServerUri { get; } = new("http://localhost", UriKind.Absolute);
    }
}
