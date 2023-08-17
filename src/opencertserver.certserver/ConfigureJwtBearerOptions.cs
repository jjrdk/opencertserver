namespace OpenCertServer.CertServer;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

internal class ConfigureJwtBearerOptions : IPostConfigureOptions<JwtBearerOptions>
{
    private readonly JwtParameters _parameters;

    public ConfigureJwtBearerOptions(JwtParameters parameters)
    {
        _parameters = parameters;
    }

    /// <inheritdoc />
    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        options.Authority = _parameters.Authority;
        options.RefreshOnIssuerKeyNotFound = true;
        options.RequireHttpsMetadata = true;
        options.SaveToken = true;
    }
}

internal record JwtParameters
{
    public required string Authority { get; init; }
}
