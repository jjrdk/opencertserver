using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using OpenCertServer.Ca;
using opencertserver.ca.server;

[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]

namespace OpenCertServer.CertServer;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Server.Extensions;
using Acme.Server.Middleware;
using Est.Server;

public sealed class Program
{
    [UnconditionalSuppressMessage("AOT",
        "IL3050:Calling members annotated with 'RequiresDynamicCodeAttribute' may break functionality when AOT compiling.",
        Justification = "<Pending>")]
    public static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            throw new Exception("No configuration values passed");
        }

        var builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddEnvironmentVariables().AddCommandLine(args);
        var services = builder.Services;
        var portIndex = Array.IndexOf(args, "--port");
        var port = portIndex >= 0 ? int.Parse(args[portIndex + 1]) : 5001;
        var dn = Array.IndexOf(args, "--dn");
        if (dn >= 0)
        {
            var name = args[dn + 1];
            services = services.AddInMemoryEstServer(
                new X500DistinguishedName(name.StartsWith("CN=") ? name : $"CN={name}"));
        }
        else
        {
            var rsaCert = await CreateCert(args, "--rsa", "--rsa-key");
            var ecdsaCert = await CreateCert(args, "--ec", "--ec-key");

            services = services.AddEstServer(rsaCert, ecdsaCert);
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
            options.ConfigureHttpsDefaults(https =>
            {
                using var ecdsa = ECDsa.Create();
                var ca = options.ApplicationServices.GetRequiredService<ICertificateAuthority>();
                var certificateRequest = new CertificateRequest($"CN=localhost", ecdsa, HashAlgorithmName.SHA256);
                certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                certificateRequest.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
                var subjectAlternativeNameBuilder = new SubjectAlternativeNameBuilder();
                subjectAlternativeNameBuilder.AddDnsName("localhost");
                certificateRequest.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());
                var response = ca.SignCertificateRequest(
                    certificateRequest);
                if (response is not SignCertificateResponse.Success success)
                {
                    throw new InvalidOperationException("Could not create server certificate");
                }

                https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                var cert = success.Certificate.CopyWithPrivateKey(ecdsa);
                https.ServerCertificate = cert;
            });
        }).UseUrls($"https://*:{port}");
        var app = builder.Build();
        app.UseForwardedHeaders(forwardedHeadersOptions)
            .UseHealthChecks("/health")
            .UseAcmeServer()
            .UseEstServer()
            .UseCertificateAuthorityServer();
        await app.RunAsync();
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
        var pem = await file.ReadToEndAsync();
        var keyPem = await keyFile.ReadToEndAsync();
        var x509 = key == null
            ? X509Certificate2.CreateFromPem(pem)
            : X509Certificate2.CreateFromPem(pem, keyPem);
        return x509;
    }
}
