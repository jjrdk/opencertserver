namespace OpenCertServer.CertServer;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

internal class ConfigureJwtBearerOptions : IPostConfigureOptions<JwtBearerOptions>
{
    /// <inheritdoc />
    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        options.Authority = "https://identity.reimers.dk";
        options.RefreshOnIssuerKeyNotFound = true;
        options.RequireHttpsMetadata = true;
        options.SaveToken = true;
    }
}
