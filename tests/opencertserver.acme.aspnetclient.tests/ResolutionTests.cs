namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using AspNet.EncryptWeMust;
using Certes;
using global::Certes;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

public sealed class ResolutionTests
{
    [Fact]
    public void Go()
    {
        var thing = WebHost.CreateDefaultBuilder()
            .ConfigureLogging(options => options.AddConsole())
            .ConfigureServices(services =>
            {
                services.AddAcmeClient(new LetsEncryptOptions()
                {
                    Email = "some-email@github.com",
                    UseStaging = true,
                    Domains = new[] {"test.com"},
                    TimeUntilExpiryBeforeRenewal = TimeSpan.FromDays(30),
                    CertificateSigningRequest = new CsrInfo()
                    {
                        CountryName = "CountryNameStuff",
                        Locality = "LocalityStuff",
                        Organization = "OrganizationStuff",
                        OrganizationUnit = "OrganizationUnitStuff",
                        State = "StateStuff"
                    }
                });
                services.AddTransient<HttpClient>();
                services.AddAcmeFileCertificatePersistence();
                services.AddAcmeFileChallengePersistence();
            })
            .Configure(appBuilder => { appBuilder.UseAcmeClient(); })
            .Build();

        thing.Services.GetRequiredService<IAcmeRenewalService>();
    }
}