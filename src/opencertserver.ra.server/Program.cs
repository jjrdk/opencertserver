using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using OpenCertServer.Ca.Client;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509Extensions;
using OpenCertServer.Est.Server;
using OpenCertServer.Est.Server.Handlers;
using OpenCertServer.Ra;
using OpenCertServer.Ra.Server;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;
configuration.AddEnvironmentVariables();

// A standalone registration authority has no CA core. It issues, revokes, and serves EST over a
// trusted HTTPS connection to a backing certificate authority. AddCaClient registers the backing-CA
// client and exposes it as this host's ICertificateAuthority (a RemoteCertificateAuthority), so EST
// /cacerts, /csrattrs, and /simpleenroll all resolve through the backing CA. The RA peer client is the
// outbound delegator the RA uses for scoped enrollment.
var services = builder.Services
    .AddCaClient(CaClientOptions.FromConfiguration(configuration))
    .AddRaPeerClient(RaPeerOptions.FromConfiguration(configuration))
    // EST support on the RA: the built-in empty template loader plus the EST services. EST handlers
    // take the issuing authority from ICertificateAuthority, which the CA client provides (remote).
    .AddEstServer<CsrTemplateLoader>();

// EST enrollment, re-enrollment, and server-keygen are guarded by a signature-verified JWT. The RA
// refuses to start without a signing key, so it can never accept a signature-unverified token; scope
// and identity authority remain with the backing CA.
services.ConfigureRaJwt(configuration);

services.AddAuthorization();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// EST endpoints (RFC 7030): /cacerts and /csrattrs are anonymous; enrollment, re-enrollment, and
// server keygen require a bearer token. Issuance is delegated to the backing CA.
var enrollPolicy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme)
    .RequireAuthenticatedUser()
    .Build();
app.MapEstServer(
    enrollPolicy: enrollPolicy,
    reEnrollPolicy: enrollPolicy,
    serverKeyGenPolicy: enrollPolicy);

// The RA front endpoint: an outbound delegator. It reads a proof-of-possession CSR, forwards it to the
// trusted backing CA, and returns the signed chain. Scope and identity authority remain with the CA;
// the RA only adds policy and audit around the delegated request. The optional "profile" query selects
// which CA profile the request enrolls against, so one RA can offer several profiles; it falls back to
// the CA's default profile when absent.
app.MapPost("/ra/enroll", async (HttpContext context, ICertificateAuthority ca, CancellationToken ct) =>
{
    var profile = context.Request.Query["profile"].ToString();
    using var reader = new StreamReader(context.Request.Body);
    var body = await reader.ReadToEndAsync(ct);
    var response = await ca.SignCertificateRequestPem(
        body,
        profileName: string.IsNullOrWhiteSpace(profile) ? null : profile,
        cancellationToken: ct);
    if (response is SignCertificateResponse.Success success)
    {
        return Results.Content(
            success.Certificate.ToPemChain(success.Issuers),
            "application/x-pem-file");
    }

    return Results.BadRequest(response is SignCertificateResponse.Error error
        ? string.Join(Environment.NewLine, error.Errors)
        : "The certificate request could not be signed.");
});

// The RA can request the set of profiles the backing CA currently supports, refresh it on demand, and
// offer only that set to its own clients. This is the discovery path for "support an updated profile
// set": only profile names cross the wire, never the profile material.
app.MapGet("/ra/profiles", async (HttpContext context, ICertificateAuthority ca, CancellationToken ct) =>
{
    var names = await ca.GetSupportedProfiles(ct);
    return Results.Content(
        string.Join(Environment.NewLine, names),
        "text/plain");
});

app.MapGet("/health", () => Results.Ok());

app.Run();
