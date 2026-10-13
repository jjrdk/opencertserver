namespace OpenCertServer.Est.Server.BasicAuthentication;

using Microsoft.AspNetCore.Authentication;

/// <summary>Registers the EST Basic authentication scheme.</summary>
public static class EstBasicAuthenticationExtensions
{
    /// <summary>
    /// Adds HTTP Basic authentication for the EST endpoints (RFC 7030 §3.2.3). The scheme is off until
    /// users are configured, and it takes effect only where a host lists it in the authorization policies
    /// it passes to <c>UseEstServer</c>.
    /// </summary>
    public static AuthenticationBuilder AddEstBasicAuthentication(
        this AuthenticationBuilder builder,
        Action<EstBasicAuthenticationOptions>? configure = null)
    {
        return builder.AddScheme<EstBasicAuthenticationOptions, EstBasicAuthenticationHandler>(
            EstBasicAuthenticationDefaults.AuthenticationScheme,
            configure ?? (_ => { }));
    }
}
