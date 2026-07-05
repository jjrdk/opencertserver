namespace OpenCertServer.Acme.Server.Tests.StepDefinitions;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
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
using AcmeAccount = OpenCertServer.Acme.Abstractions.Model.Account;
using AcmeChallenge = OpenCertServer.Acme.Abstractions.Model.Challenge;
using AcmeError = OpenCertServer.Acme.Abstractions.Model.AcmeError;
using AcmeIdentifier = OpenCertServer.Acme.Abstractions.Model.Identifier;
using AcmeOrder = OpenCertServer.Acme.Abstractions.Model.Order;

/// <summary>
/// Creates a minimal ACME test server for directory and e2e tests.
/// </summary>
internal static class TestAcmeServerFactory
{
    [UnconditionalSuppressMessage("Trimming", "IL2111", Justification = "Test runtime")]
    [UnconditionalSuppressMessage("AOT", "IL3050", Justification = "Test runtime")]
    public static TestServer Create(IValidateDeviceAttestChallenges? deviceAttestValidator = null)
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
        IValidateDeviceAttestChallenges deviceAttestValidator)
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

        services.Replace(ServiceDescriptor.Scoped<IValidateHttp01Challenges, AlwaysValidHttp01Validator>());
        services.Replace(ServiceDescriptor.Scoped<IValidateDns01Challenges, AlwaysValidDns01Validator>());
        services.Replace(ServiceDescriptor.Scoped<IValidateDeviceAttestChallenges>(_ => deviceAttestValidator));
    }

    // ─── Test doubles ────────────────────────────────────────────────────────

    internal sealed class AlwaysValidDeviceAttestValidator : IValidateDeviceAttestChallenges
    {
        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge, AcmeAccount account, CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private sealed class AlwaysValidHttp01Validator : IValidateHttp01Challenges
    {
        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge, AcmeAccount account, CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private sealed class AlwaysValidDns01Validator : IValidateDns01Challenges
    {
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
            string? profile, string csr, IEnumerable<AcmeIdentifier> identifiers,
            DateTimeOffset? notBefore, DateTimeOffset? notAfter,
            CancellationToken cancellationToken)
            => Task.FromResult<(byte[]?, AcmeError?)>(([0x00], null));
    }
}
