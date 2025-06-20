using System.Runtime.CompilerServices;
[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]

namespace OpenCertServer.CertServer;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Server.Middleware;
using OpenCertServer.Est.Server;

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
        var dn = Array.IndexOf(args, "--dn");
        if (dn >= 0)
        {
            var name = args[dn + 1];
            services = services.AddEstServer(new X500DistinguishedName(name.StartsWith("CN=") ? name : $"CN={name}"));
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

        _ = services.AddAuthentication().AddJwtBearer().AddCertificate()
            .Services
            .AddAcmeServer(builder.Configuration)
            .AddAcmeInMemoryStore()
            .AddSingleton(new JwtParameters { Authority = authority })
            .AddSingleton<ICsrValidator, DefaultCsrValidator>()
            .AddSingleton<ICertificateIssuer, DefaultIssuer>()
            .ConfigureOptions<ConfigureJwtBearerOptions>()
            .ConfigureOptions<ConfigureCertificateAuthenticationOptions>()
            .AddHealthChecks();
        var app = builder.Build();
        app.UseForwardedHeaders(forwardedHeadersOptions).UseHealthChecks("/health").UseAcmeServer().UseEstServer();
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
        forwardedHeadersOptions.KnownNetworks.Clear();
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
