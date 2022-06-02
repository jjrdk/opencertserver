using System.Runtime.CompilerServices;

[assembly:InternalsVisibleTo("opencertserver.certserver.tests")]

namespace opencertserver.certserver;

using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Server.Middleware;
using OpenCertServer.Ca;
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

internal class DefaultCsrValidator : ICsrValidator
{
    /// <inheritdoc />
    public Task<(bool isValid, AcmeError? error)> ValidateCsrAsync(Order order, string csr, CancellationToken cancellationToken)
    {
        return Task.FromResult((true, (AcmeError?)null));
    }
}

internal class DefaultIssuer : ICertificateIssuer
{
    private readonly ICertificateAuthority _ca;

    public DefaultIssuer(ICertificateAuthority ca)
    {
        _ca = ca;
    }

    /// <inheritdoc />
    public Task<(bool isValid, AcmeError? error)> ValidateCsrAsync(Order order, string csr, CancellationToken cancellationToken)
    {
        return Task.FromResult((true, (AcmeError?)null));
    }

    /// <inheritdoc />
    public async Task<(byte[]? certificate, AcmeError? error)> IssueCertificate(string csr, CancellationToken cancellationToken)
    {
        await Task.Yield();
        var cert = _ca.SignCertificateRequest(csr);
        return cert switch
        {
            SignCertificateResponse.Success success => (success.Certificate.RawData, null),
            SignCertificateResponse.Error error => (null, new AcmeError(string.Join(", ", error.Errors), "")),
            _ => throw new ArgumentException()
        };
    }
}
