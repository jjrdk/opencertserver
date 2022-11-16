using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]

namespace OpenCertServer.CertServer;

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
            var rsaCert = await CreateRsaCert(args);
            var ecdsaCert = await CreateEcdsaCert(args);

            services = services.AddEstServer(rsaCert, ecdsaCert);
        }

        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.All,
            ForwardLimit = null,
            AllowedHosts = Array.Empty<string>()
        };
        forwardedHeadersOptions.KnownNetworks.Clear();
        forwardedHeadersOptions.KnownProxies.Clear();

        _ = services.AddAcmeServer(builder.Configuration)
            .AddAcmeFileStore(builder.Configuration)
            .AddSingleton<ICsrValidator, DefaultCsrValidator>()
            .AddSingleton<ICertificateIssuer, DefaultIssuer>()
            .ConfigureOptions<ConfigureJwtBearerOptions>();
        var app = builder.Build();
        app.UseForwardedHeaders(forwardedHeadersOptions).UseAcmeServer().UseEstServer();
        await app.RunAsync();
    }

    private static async Task<X509Certificate2> CreateEcdsaCert(string[] args)
    {
        var ecdsa = args[Array.IndexOf(args, "--ec") + 1];
        var ecdsaKeyIndex = Array.IndexOf(args, "--ec-key");
        var ecdsaKey = ecdsaKeyIndex >= 0 ? args[ecdsaKeyIndex + 1] : null;
        using var ecdsaFile = File.OpenText(ecdsa);
        using var ecdsaKeyFile = ecdsaKey == null ? TextReader.Null : File.OpenText(ecdsaKey);
        var ecdsaPem = await ecdsaFile.ReadToEndAsync();
        var ecdsaKeyPem = await ecdsaKeyFile.ReadToEndAsync();
        var ecdsaCert = ecdsaKey == null
            ? X509Certificate2.CreateFromPem(ecdsaPem)
            : X509Certificate2.CreateFromPem(ecdsaPem, ecdsaKeyPem);
        return ecdsaCert;
    }

    private static async Task<X509Certificate2> CreateRsaCert(string[] args)
    {
        var rsa = args[Array.IndexOf(args, "--rsa") + 1];
        var rsaKeyIndex = Array.IndexOf(args, "--rsa-key");
        var rsaKey = rsaKeyIndex >= 0 ? args[rsaKeyIndex + 1] : null;
        using var rsaFile = File.OpenText(rsa);
        using var rsaKeyFile = rsaKey == null ? TextReader.Null : File.OpenText(rsaKey);
        var rsaPem = await rsaFile.ReadToEndAsync();
        var rsaKeyPem = await rsaKeyFile.ReadToEndAsync();
        var rsaCert = rsaKey == null
            ? X509Certificate2.CreateFromPem(rsaPem)
            : X509Certificate2.CreateFromPem(rsaPem, rsaKeyPem);
        return rsaCert;
    }
}
