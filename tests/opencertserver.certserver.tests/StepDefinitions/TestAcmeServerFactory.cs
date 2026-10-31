using CertesSlim.Acme;
using CertesSlim.Acme.Resource;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server;
using OpenCertServer.Acme.Server.Configuration;
using OpenCertServer.Acme.Server.Extensions;

using AcmeAccount = Acme.Abstractions.Model.Account;
using AcmeChallenge = Acme.Abstractions.Model.Challenge;
using AcmeOrder = Acme.Abstractions.Model.Order;

/// <summary>
/// Creates a minimal ACME test server for directory and e2e tests.
/// </summary>
internal static class TestAcmeServerFactory
{
    [UnconditionalSuppressMessage("Trimming", "IL2111", Justification = "Test runtime")]
    [UnconditionalSuppressMessage("AOT", "IL3050", Justification = "Test runtime")]
    public static TestServer Create(IValidateChallenges? deviceAttestValidator = null)
    {
        deviceAttestValidator ??= new AlwaysValidDeviceAttestValidator();

        var host = new HostBuilder()
            .ConfigureWebHost(builder =>
            {
                builder
                    .UseTestServer()
                    .UseUrls("https://localhost")
                    .ConfigureAppConfiguration(c => c.AddEnvironmentVariables())
                    .ConfigureServices((ctx, svc) => ConfigureServices(ctx, svc, deviceAttestValidator))
                    .Configure(static app => app.UseAcmeServer());
            })
            .Build();
        host.Start();
        return host.GetTestServer();
    }

    [UnconditionalSuppressMessage("Trimming", "IL2067", Justification = "Test runtime")]
    [UnconditionalSuppressMessage("Trimming", "IL2111", Justification = "Test runtime")]
    [UnconditionalSuppressMessage("AOT", "IL3050", Justification = "Test runtime")]
    private static void ConfigureServices(
        WebHostBuilderContext ctx,
        IServiceCollection services,
        IValidateChallenges deviceAttestValidator)
    {
        services
            .AddAcmeServer(ctx.Configuration, acmeServerOptions: new AcmeServerOptions
            {
                HostedWorkers = new BackgroundServiceOptions
                {
                    EnableValidationService = false,
                    EnableIssuanceService = false
                }
            })
            .AddAcmeInMemoryStore()
            .AddRouting()
            .AddAuthorization()
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, _ => { });

        services.AddSingleton<ICsrValidator, StubCsrValidator>();
        services.AddSingleton<IIssueCertificates, StubCertificateIssuer>();

        // The factory resolves IValidateChallenges as a collection and routes by AppliesTo,
        // so remove the production validator registrations and add the test doubles instead
        // (one per challenge type).
        for (var i = services.Count - 1; i >= 0; i--)
        {
            if (services[i].ServiceType == typeof(IValidateChallenges))
                services.RemoveAt(i);
        }

        services.Add(ServiceDescriptor.Scoped<IValidateChallenges, AlwaysValidHttp01Validator>());
        services.Add(ServiceDescriptor.Scoped<IValidateChallenges, AlwaysValidDns01Validator>());
        services.Add(ServiceDescriptor.Scoped<IValidateChallenges>(_ => deviceAttestValidator));
    }

    // ─── Test doubles ────────────────────────────────────────────────────────

    internal sealed class AlwaysValidDeviceAttestValidator : IValidateChallenges
    {
        public string AppliesTo => ChallengeTypes.DeviceAttest01;

        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge, AcmeAccount account, CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private sealed class AlwaysValidHttp01Validator : IValidateChallenges
    {
        public string AppliesTo => ChallengeTypes.Http01;

        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge, AcmeAccount account, CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private sealed class AlwaysValidDns01Validator : IValidateChallenges
    {
        public string AppliesTo => ChallengeTypes.Dns01;

        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge, AcmeAccount account, CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private sealed class StubCsrValidator : ICsrValidator
    {
        public Task<(bool isValid, AcmeError? error)> ValidateCsr(
            AcmeOrder order, string csr, CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private sealed class StubCertificateIssuer : IIssueCertificates
    {
        public Task<(byte[]? certificate, AcmeError? error)> IssueCertificate(
            string? profile, string csr, IEnumerable<Identifier> identifiers,
            DateTimeOffset? notBefore, DateTimeOffset? notAfter,
            CancellationToken cancellationToken)
            => Task.FromResult<(byte[]?, AcmeError?)>(([0x00], null));
    }
}
