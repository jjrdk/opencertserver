using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Options;

namespace OpenCertServer.Est.Tests.Configuration;

internal class ConfigureOauthOptions : IPostConfigureOptions<JwtBearerOptions>
{
    public void PostConfigure(string? name, JwtBearerOptions options)
    {
        options.SaveToken = true;
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = c =>
            {
                var hasToken = c.Request.Headers.TryGetValue("Authorization", out var token);
                if (!hasToken)
                {
                    c.NoResult();
                    return Task.CompletedTask;
                }
                token = token.ToString().Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase);
                if(token != "valid-jwt")
                {
                    c.NoResult();
                    return Task.CompletedTask;
                }

                c.Principal =
                    new ClaimsPrincipal(
                        new ClaimsIdentity([new Claim("role", "user")],
                            JwtBearerDefaults.AuthenticationScheme));
                c.Properties = new OAuthChallengeProperties
                {
                    AllowRefresh = false, RedirectUri = "http://localhost",
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(1), IssuedUtc = DateTimeOffset.UtcNow,
                    IsPersistent = false, Scope = ["openid"]
                };
                c.Success();

                return Task.CompletedTask;
            }
        };
    }
}
