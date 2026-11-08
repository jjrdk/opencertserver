using OpenCertServer.Acme;
using OpenCertServer.Acme.Server;
using OpenCertServer.Acme.Server.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Remote;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;
configuration.AddEnvironmentVariables();

// A standalone ACME host has no CA core. The ACME server issues and revokes through a backing
// certificate authority over a trusted HTTPS connection. AcmeRemoteServiceCollectionExtensions
// registers the backing-CA client and the RemoteIssuer as the host's IIssueCertificates.
builder.Services
    .AddAcmeServer(configuration)
    .AddAcmeInMemoryStore()
    .AddAcmeRemoteCa(configuration)
    .AddSingleton<ICsrValidator, DefaultCsrValidator>();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        var authority = configuration["AcmeServer:Authority"];
        if (!string.IsNullOrWhiteSpace(authority))
        {
            options.Authority = authority;
            options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = authority,
                ValidAudiences = configuration
                    .GetSection("AcmeServer:Audiences")
                    .GetChildren()
                    .Select(child => child.Value)
                    .OfType<string>()
                    .ToArray(),
                ClockSkew = TimeSpan.FromMinutes(5),
            };
        }
    })
    .AddCertificate();

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAcmeServer();

app.Run();
