using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Ra.Server;

/// <summary>
/// Configures the registration authority's inbound EST authentication. EST enrollment, re-enrollment,
/// and server-keygen are protected by a signature-verified JWT, so the RA refuses to start when no
/// signing key is available: a JWT whose signature cannot be verified would be accepted, opening the
/// enrollment surface to any well-formed token. A symmetric key (<c>Jwt:SymmetricKey</c>) verifies
/// HS256/384/512 tokens; an <c>Authority</c>/<c>MetadataAddress</c> fetches the issuer's signing keys.
/// </summary>
public static class RaServerAuthentication
{
    /// <summary>
    /// Registers the JWT bearer scheme that guards EST enrollment and throws when no signing key is
    /// configured, so a RA never starts with signature-unverified enrollment.
    /// </summary>
    public static void ConfigureRaJwt(this IServiceCollection services, IConfiguration configuration)
    {
        var section = configuration.GetSection("Jwt");
        var symmetricKey = section["SymmetricKey"];
        var authority = section["MetadataAddress"] ?? section["Authority"];

        // Fail closed: EST enrollment must be protected by a signature-verified JWT. When neither a
        // symmetric key nor an issuer metadata endpoint is configured the RA cannot verify the token
        // signature, so it refuses to start rather than accept any well-formed token.
        if (string.IsNullOrWhiteSpace(symmetricKey) && string.IsNullOrWhiteSpace(authority))
        {
            throw new InvalidOperationException(
                "The RA EST enrollment endpoint requires a signing key (Jwt:SymmetricKey, Jwt:Authority, " +
                "or Jwt:MetadataAddress). The registration authority refuses to start with a " +
                "signature-unverified JWT.");
        }

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    // The vulnerability this method closes: the signature is always verified. A token
                    // signed by any key other than the RA's (or its issuer's) is rejected.
                    ValidateIssuerSigningKey = true,
                };

                if (!string.IsNullOrWhiteSpace(symmetricKey))
                {
                    options.TokenValidationParameters.IssuerSigningKey =
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(symmetricKey!));
                }
                else
                {
                    // Asymmetric: resolve the issuer's signing keys from the discovery metadata.
                    options.Authority = authority!;
                    options.TokenValidationParameters.ValidIssuers =
                        configuration.GetSection("Jwt:ValidIssuers").GetChildren()
                            .Select(child => child.Value)
                            .Where(value => !string.IsNullOrWhiteSpace(value))
                            .OfType<string>()
                            .ToArray();
                }
            });
    }
}
