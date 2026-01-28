namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using Certes;
using CertesSlim.Extensions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Xunit;

public sealed class ResolutionTests
{
    [Fact]
    public void Go()
    {
        var thing = new HostBuilder().ConfigureWebHost(b =>
            {
                b.ConfigureLogging(options => options.AddConsole())
                    .ConfigureServices(services =>
                    {
                        services.AddAcmeClient(new LetsEncryptOptions()
                        {
                            Email = "some-email@github.com",
                            UseStaging = true,
                            Domains = ["test.com"],
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
                    .Configure(appBuilder => { appBuilder.UseAcmeClient(); });
            })
            .Build();

        thing.Services.GetRequiredService<IAcmeRenewalService>();
    }
}
