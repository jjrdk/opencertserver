namespace OpenCertServer.CertServer;

using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

internal class ConfigureJwtBearerOptions(JwtParameters parameters) : IPostConfigureOptions<JwtBearerOptions>
{
    /// <inheritdoc />
    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        options.Authority = parameters.Authority;
        options.RefreshOnIssuerKeyNotFound = true;
        options.RequireHttpsMetadata = true;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = true,
            ValidIssuer = parameters.Authority,
            ClockSkew = TimeSpan.FromMinutes(5)
        };
    }
}

internal record JwtParameters
{
    public required string Authority { get; init; }
}
