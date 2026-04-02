using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Est.Server.Handlers;

[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]

namespace OpenCertServer.CertServer;

using System.Linq;
using System.Numerics;
using System.Security.Authentication;
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
            var rsaProfile = await CreateProfile(
                args,
                builder.Configuration,
                profileName: "rsa",
                certArgument: "--rsa",
                keyArgument: "--rsa-key",
                publishedArgument: "--rsa-published",
                getPrivateKey: cert => cert.GetRSAPrivateKey()).ConfigureAwait(false);
            var ecdsaProfile = await CreateProfile(
                args,
                builder.Configuration,
                profileName: "ecdsa",
                certArgument: "--ec",
                keyArgument: "--ec-key",
                publishedArgument: "--ec-published",
                getPrivateKey: cert => cert.GetECDsaPrivateKey()).ConfigureAwait(false);
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
        builder.WebHost.UseKestrel(options =>
            {
                options.AddServerHeader = false;
                options.ConfigureHttpsDefaults(httpsOptions =>
                {
                    // RFC 7030 requires TLS 1.1 or later for EST; prefer TLS 1.2+ in practice.
                    httpsOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                    // Kestrel presents an X.509 server certificate that is expected to conform to RFC5280.
                    // Leave TLS session resumption enabled (the default) because RFC 7030 recommends session resumption support.
                });
            })
            .UseUrls($"https://*:{port}");
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

    private static async Task<CaProfile> CreateProfile(
        string[] args,
        IConfiguration configuration,
        string profileName,
        string certArgument,
        string keyArgument,
        string publishedArgument,
        Func<X509Certificate2, AsymmetricAlgorithm?> getPrivateKey)
    {
        var certificate = await CreateCert(args, certArgument, keyArgument).ConfigureAwait(false);
        var privateKey = getPrivateKey(certificate)
            ?? throw new InvalidOperationException(
                $"The certificate configured for profile '{profileName}' does not expose a compatible private key.");
        var activeCertificate = X509Certificate2.CreateFromPem(certificate.ExportCertificatePem());
        var publishedCertificatePath = GetArgumentValue(args, publishedArgument) ?? configuration[$"{profileName}:PublishedPem"];

        return new CaProfile
        {
            Name = profileName,
            CertificateChain = [activeCertificate],
            PublishedCertificateChain = await LoadPublishedCertificateChain(publishedCertificatePath, activeCertificate)
                .ConfigureAwait(false),
            CertificateValidity = TimeSpan.FromDays(90),
            CrlNumber = BigInteger.Zero,
            PrivateKey = privateKey
        };
    }

    private static string? GetArgumentValue(string[] args, string argumentName)
    {
        var index = Array.IndexOf(args, argumentName);
        return index >= 0 && index + 1 < args.Length
            ? args[index + 1]
            : null;
    }

    private static async Task<X509Certificate2Collection> LoadPublishedCertificateChain(
        string? certificateBundlePath,
        X509Certificate2 activeCertificate)
    {
        if (string.IsNullOrWhiteSpace(certificateBundlePath))
        {
            return [];
        }

        var pem = await File.ReadAllTextAsync(certificateBundlePath).ConfigureAwait(false);
        X509Certificate2Collection importedCertificates = [];
        importedCertificates.ImportFromPem(pem);
        if (importedCertificates.Count == 0)
        {
            throw new InvalidOperationException(
                $"The published EST certificate bundle '{certificateBundlePath}' did not contain any PEM certificates.");
        }

        X509Certificate2Collection publishedCertificates = [];
        AddUniqueCertificate(publishedCertificates, X509Certificate2.CreateFromPem(activeCertificate.ExportCertificatePem()));
        foreach (var certificate in importedCertificates)
        {
            AddUniqueCertificate(publishedCertificates, certificate);
        }

        return publishedCertificates;
    }

    private static void AddUniqueCertificate(
        X509Certificate2Collection collection,
        X509Certificate2 certificate)
    {
        if (collection.Any(existing =>
                string.Equals(existing.Thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)))
        {
            certificate.Dispose();
            return;
        }

        collection.Add(certificate);
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
