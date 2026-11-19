using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using OpenCertServer.Est.Server;
using OpenCertServer.Est.Server.Handlers;
using OpenCertServer.Host.Ra;
using OpenCertServer.Ra;

// Hardened registration-authority appliance. Unlike opencertserver.ra.server (a plain RA front-end),
// this host hardens the TLS/Kestrel surface and guards its RA operator endpoints with a role-checked
// JWT, mirroring the central CA's RA role. Every issuance and revocation is delegated to a backing
// certificate authority over a trusted HTTPS connection; the RA hosts policy and audit, never the CA
// core. This project intentionally does not reference opencertserver.ca or opencertserver.ca.server.
var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;
configuration.AddEnvironmentVariables();

var appliance = ApplianceOptions.Read(configuration);
var authority = configuration["Jwt:Authority"];
var audiences = configuration.GetSection("Jwt:Audiences").GetChildren()
    .Select(value => value.Value).OfType<string>().Where(value => !string.IsNullOrWhiteSpace(value)).ToArray();
if (!Uri.TryCreate(authority, UriKind.Absolute, out var authorityUri) || authorityUri.Scheme != "https")
{
    throw new InvalidOperationException("Set Jwt:Authority to an HTTPS identity provider for RA operators.");
}

if (audiences.Length == 0)
{
    throw new InvalidOperationException("Set Jwt:Audiences for RA operator authentication.");
}

using var identity = X509Certificate2.CreateFromPemFile(
    configuration["Ra:ClientCertificatePath"]
     ?? throw new InvalidOperationException("Set Ra:ClientCertificatePath."),
    configuration["Ra:ClientPrivateKeyPath"]
     ?? throw new InvalidOperationException("Set Ra:ClientPrivateKeyPath."));

// The CA the RA delegates to. A backing CA is always an HTTPS endpoint; RaPeerOptions.FromConfiguration
// (below) reads Ra:PeerUrl and rejects a non-HTTPS peer, and the RA presents its own client certificate
// while validating the CA chain against the operator-supplied trust roots.
var roots = new X509Certificate2Collection();
try
{
    foreach (var path in configuration.GetSection("Ra:CaTrustRoots").GetChildren())
    {
        var imported = new X509Certificate2Collection();
        imported.ImportFromPemFile(path.Value
         ?? throw new InvalidOperationException("Ra:CaTrustRoots requires PEM file paths."));
        if (imported.Count == 0)
        {
            throw new InvalidOperationException("An RA peer trust file contains no certificates.");
        }

        roots.AddRange(imported);
    }

    builder.Services.AddRaPeerClient(RaPeerOptions.FromConfiguration(configuration), handler =>
    {
        handler.ClientCertificates.Add(identity);
        handler.AllowAutoRedirect = false;
        handler.SslProtocols = appliance.Protocols;
        if (roots.Count > 0)
        {
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
            {
                if (certificate is null ||
                    (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
                {
                    return false;
                }

                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.AddRange(roots);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.ApplicationPolicy.Add(new("1.3.6.1.5.5.7.3.1"));
                return chain.Build(certificate);
            };
        }
    });

    // EST support on the RA: the built-in template loader plus EST services, issuing through the CA peer.
    builder.Services.AddEstServer<CsrTemplateLoader>();

    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.TokenValidationParameters.ValidAudiences = audiences;
    });
    builder.Services.AddAuthorization(options => options.AddPolicy("ra_operator",
        policy => policy.RequireAuthenticatedUser().RequireRole("ra_operator")));
    builder.Services.AddHealthChecks();
    builder.Services.AddHsts(options => options.MaxAge = TimeSpan.FromDays(180));
    builder.Services.AddHostFiltering(options =>
    {
        options.AllowedHosts = (configuration["AllowedHosts"] ?? "localhost")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        options.AllowEmptyHosts = false;
        options.IncludeFailureMessage = false;
    });
    builder.WebHost.UseKestrel(options =>
    {
        options.AddServerHeader = false;
        options.Limits.MaxRequestBodySize = 64 * 1024;
        options.ConfigureHttpsDefaults(https =>
        {
            https.SslProtocols = appliance.Protocols;
            https.OnAuthenticate = (_, authentication) =>
                authentication.EnabledSslProtocols = appliance.Protocols;
        });
    }).UseUrls($"https://*:{configuration.GetValue("port", 5001)}");
    await using var app = builder.Build();
    _ = app.Services.GetRequiredService<RaPeerClient>();
    app.UseHsts().UseHostFiltering();
    app.Use(async (context, next) =>
    {
        context.Response.OnCompleted(() =>
        {
            app.Logger.LogWarning("RA audit {TraceId} {StatusCode} {Authenticated}",
                context.TraceIdentifier,
                context.Response.StatusCode, context.User.Identity?.IsAuthenticated == true);
            return Task.CompletedTask;
        });
        await next(context);
    });
    app.UseAuthentication().UseAuthorization();
    app.MapHealthChecks("/health");
    app.MapPost("/ra/enroll", Enroll).RequireAuthorization("ra_operator");
    app.MapPost("/ra/renew", Enroll).RequireAuthorization("ra_operator");
    app.MapDelete("/ra/revoke", async (HttpContext context, RaPeerClient peer) =>
    {
        var serial = context.Request.Query["sn"].ToString();
        var reasonName = context.Request.Query["reason"].ToString();
        if (string.IsNullOrWhiteSpace(serial) ||
            !Enum.TryParse<X509RevocationReason>(reasonName, true, out var reason) ||
            !Enum.IsDefined(reason) ||
            !string.Equals(reasonName, reason.ToString(), StringComparison.OrdinalIgnoreCase))
        {
            app.Logger.LogWarning("Rejected RA revocation with missing serial or invalid reason");
            return Results.BadRequest("Supply sn and a valid X509RevocationReason name.");
        }

        try
        {
            return await peer.RevokeAsync(identity, serial, reason, context.RequestAborted)
                ? Results.NoContent()
                : Results.NotFound();
        }
        catch (HttpRequestException exception)
        {
            return PeerFailure(context, exception);
        }
    }).RequireAuthorization("ra_operator");
    await app.RunAsync().ConfigureAwait(false);
}
finally
{
    foreach (var root in roots) root.Dispose();
}

return;

static async Task<IResult> Enroll(HttpContext context, RaPeerClient peer)
{
    using var reader = new StreamReader(context.Request.Body);
    var csr = await reader.ReadToEndAsync(context.RequestAborted);
    if (string.IsNullOrWhiteSpace(csr))
    {
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("RaAppliance")
            .LogWarning("Rejected empty RA enrollment request");
        return Results.BadRequest("Supply a PEM PKCS#10 request.");
    }

    try
    {
        // The optional "profile" query selects which CA profile the enrollment targets, mirroring the RA
        // server; it falls back to the CA's default profile when absent.
        var profile = context.Request.Query["profile"].ToString();
        var profileName = string.IsNullOrWhiteSpace(profile) ? null : profile;
        var certificate = await peer.EnrollAsync(csr, profileName, context.RequestAborted);
        return Results.Text(certificate, "application/pem-certificate-chain");
    }
    catch (HttpRequestException exception)
    {
        return PeerFailure(context, exception);
    }
}

static IResult PeerFailure(HttpContext context, HttpRequestException exception)
{
    context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("RaAppliance")
        .LogWarning(exception, "RA peer request failed with status {StatusCode}", exception.StatusCode);
    return Results.Problem("The central CA rejected or could not complete the RA request.",
        statusCode: exception.StatusCode is System.Net.HttpStatusCode.BadRequest
         or System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.NotFound
            ? (int)exception.StatusCode.Value
            : StatusCodes.Status502BadGateway);
}

namespace OpenCertServer.Host.Ra
{
    /// <summary>Appliance hardening flags read from configuration.</summary>
    internal sealed record ApplianceOptions(bool Hardened)
    {
        public System.Security.Authentication.SslProtocols Protocols =>
            Hardened ? System.Security.Authentication.SslProtocols.Tls13
                : System.Security.Authentication.SslProtocols.Tls12 |
                System.Security.Authentication.SslProtocols.Tls13;

        public static ApplianceOptions Read(IConfiguration configuration)
        {
            var hardened = configuration.GetSection("Appliance")["Hardened"] is not { } raw ||
                bool.TryParse(raw, out var value) && value;
            return new ApplianceOptions(hardened);
        }
    }
}
