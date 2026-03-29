using System.Runtime.CompilerServices;
using OpenCertServer.Est.Server.Handlers;

[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]

namespace OpenCertServer.CertServer;

using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using Acme.Abstractions.IssuanceServices;
using Est.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Acme.Server;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Server;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            throw new Exception("No configuration values passed");
        }

        var builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddEnvironmentVariables().AddCommandLine(args)
            .AddJsonFile("appsettings.json", true, true);
        var services = builder.Services
            .AddCors(options =>
            {
                options.AddPolicy("TrustedClients", pb =>
                {
                    pb
                        .WithOrigins(
                            builder
                                .Configuration.GetRequiredSection("Cors")
                                .GetValue<string[]>("TrustedOrigins")!)
                        .AllowCredentials()
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            })
            .AddInMemoryCertificateStore();
        var port = int.TryParse(builder.Configuration.GetSection("port").Value, out var p)
            ? p
            : 5001; //portIndex >= 0 ? int.Parse(args[portIndex + 1]) : 5001;
        var index = 0;
        List<string> ocspUrls = ["http://localhost:6001/ocsp"];
        List<string> caIssuerUrls = [];
        while (index >= 0)
        {
            index = Array.IndexOf(args, "--ocsp", index);
            if (index < 0)
            {
                continue;
            }

            ocspUrls.Add(args[index + 1]);
            index++;
        }

        index = 0;
        while (index >= 0)
        {
            index = Array.IndexOf(args, "--ca-issuer", index);
            if (index < 0)
            {
                continue;
            }

            caIssuerUrls.Add(args[index + 1]);
            index++;
        }

        var dn = builder.Configuration.GetSection("dn");
        if (dn.Value is not null)
        {
            services = services.AddSelfSignedCertificateAuthority(
                    new X500DistinguishedName(
                        dn.Value.StartsWith("CN=") ? dn.Value : $"CN={dn.Value}"),
                    ocspUrls.ToArray(),
                    [],
                    caIssuerUrls.ToArray(),
                    TimeSpan.FromDays(90))
                .AddEstServer<CsrTemplateLoader>();
        }
        else
        {
            var certs = await Task.WhenAll(
                CreateCert(args, "--rsa", "--rsa-key"),
                CreateCert(args, "--ec", "--ec-key")).ConfigureAwait(false);
            var rsaProfile = new CaProfile
            {
                Name = "rsa",
                CertificateChain = [X509Certificate2.CreateFromPem(certs[0].ExportCertificatePem())],
                CertificateValidity = TimeSpan.FromDays(90),
                CrlNumber = BigInteger.Zero,
                PrivateKey = certs[0].GetRSAPrivateKey()!
            };
            var ecdsaProfile = new CaProfile
            {
                Name = "ecdsa",
                CertificateChain = [X509Certificate2.CreateFromPem(certs[1].ExportCertificatePem())],
                CertificateValidity = TimeSpan.FromDays(90),
                CrlNumber = BigInteger.Zero,
                PrivateKey = certs[1].GetRSAPrivateKey()!
            };
            services = services
                .AddCertificateAuthority(
                    new CaConfiguration(
                        new CaProfileSet("rsa", rsaProfile, ecdsaProfile),
                        ocspUrls.ToArray(),
                        [],
                        caIssuerUrls.ToArray()))
                .AddEstServer<CsrTemplateLoader>();
        }

        var a = Array.IndexOf(args, "--authority");
        var authority = a >= 0 ? args[a + 1] : "https://identity.reimers.dk";

        var forwardedHeadersOptions = CreateForwardedHeaderOptions();

        _ = services.AddAuthentication()
            .AddJwtBearer()
            .AddCertificate()
            .AddCertificateCache(options =>
            {
                options.CacheSize = 1024;
                options.CacheEntryExpiration = TimeSpan.FromMinutes(5);
            })
            .Services
            .AddAcmeServer(builder.Configuration)
            .AddAcmeInMemoryStore()
            .AddSingleton(new JwtParameters { Authority = authority })
            .AddSingleton<ICsrValidator, DefaultCsrValidator>()
            .AddSingleton<IIssueCertificates, DefaultIssuer>()
            .ConfigureOptions<ConfigureJwtBearerOptions>()
            .ConfigureOptions<ConfigureCertificateAuthenticationOptions>()
            .AddHealthChecks();
        builder.WebHost.UseKestrel(options => { options.AddServerHeader = false; }).UseUrls($"https://*:{port}");
        var app = builder.Build();
        app.UseHttpsRedirection()
            .UseCors(c => c.AllowAnyHeader().AllowAnyMethod().SetIsOriginAllowed(_ => true).AllowCredentials())
            .UseForwardedHeaders(forwardedHeadersOptions)
            .UseHealthChecks("/health")
            .UseAcmeServer()
            .UseEstServer()
            .UseCertificateAuthorityServer();
        await app.RunAsync().ConfigureAwait(false);
    }

    private static ForwardedHeadersOptions CreateForwardedHeaderOptions()
    {
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.All,
            ForwardLimit = null,
            AllowedHosts = []
        };
        forwardedHeadersOptions.KnownIPNetworks.Clear();
        forwardedHeadersOptions.KnownProxies.Clear();

        return forwardedHeadersOptions;
    }

    private static async Task<X509Certificate2> CreateCert(string[] args, string cert, string certKey)
    {
        var certIndex = args[Array.IndexOf(args, cert) + 1];
        var keyIndex = Array.IndexOf(args, certKey);
        var key = keyIndex >= 0 ? args[keyIndex + 1] : null;
        using var file = File.OpenText(certIndex);
        using var keyFile = key == null ? TextReader.Null : File.OpenText(key);
        var pem = await file.ReadToEndAsync().ConfigureAwait(false);
        var keyPem = await keyFile.ReadToEndAsync().ConfigureAwait(false);
        var x509 = key == null
            ? X509Certificate2.CreateFromPem(pem)
            : X509Certificate2.CreateFromPem(pem, keyPem);
        return x509;
    }
}
