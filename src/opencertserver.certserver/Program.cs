using System.Runtime.CompilerServices;

[assembly:InternalsVisibleTo("opencertserver.certserver.tests")]

namespace opencertserver.certserver;

using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Server.Middleware;
using OpenCertServer.Est.Server;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddEnvironmentVariables().AddCommandLine(args);
        builder.Services.AddEstServer(new X500DistinguishedName("CN=reimers.io"))
            .AddAcmeServer(builder.Configuration)
            .AddAcmeFileStore(builder.Configuration)
            .AddSingleton<ICsrValidator, DefaultCsrValidator>()
            .AddSingleton<ICertificateIssuer, DefaultIssuer>();
        var app = builder.Build();
        app.UseAcmeServer().UseEstServer();
        await app.RunAsync();
    }
}