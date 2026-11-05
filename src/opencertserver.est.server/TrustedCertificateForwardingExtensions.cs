namespace OpenCertServer.Est.Server;

using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

/// <summary>Explicit certificate forwarding from trusted TLS-terminating proxies only.</summary>
public static class TrustedCertificateForwardingExtensions
{
    public static IServiceCollection AddTrustedCertificateForwarding(
        this IServiceCollection services,
        string certificateHeader,
        Action<ForwardedHeadersOptions> configureTrustedProxies)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateHeader);
        ArgumentNullException.ThrowIfNull(configureTrustedProxies);
        if (certificateHeader.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
        {
            throw new ArgumentException("Certificate header must contain only ASCII letters, digits and hyphens.",
                nameof(certificateHeader));
        }

        var proxies = new ForwardedHeadersOptions();
        proxies.KnownProxies.Clear();
        proxies.KnownIPNetworks.Clear();
        configureTrustedProxies(proxies);
        if (proxies.KnownProxies.Count == 0 && proxies.KnownIPNetworks.Count == 0)
        {
            throw new ArgumentException(
                "Certificate forwarding requires explicitly configured trusted proxies or networks.",
                nameof(configureTrustedProxies));
        }

        services.AddSingleton(new TrustedCertificateForwardingOptions(certificateHeader, proxies));
        return services.AddCertificateForwarding(options => options.CertificateHeader = certificateHeader);
    }

    /// <summary>
    /// Call before forwarded-header processing changes RemoteIpAddress, and before authentication.
    /// The proxy must verify mTLS and strip and replace the certificate header on every request.
    /// </summary>
    public static IApplicationBuilder UseTrustedCertificateForwarding(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetRequiredService<TrustedCertificateForwardingOptions>();
        var logger = app.ApplicationServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger("OpenCertServer.Est.Server.TrustedCertificateForwarding");
        app.Use(async (context, next) =>
        {
            if (!options.IsTrusted(context.Connection.RemoteIpAddress)
             && context.Request.Headers.Remove(options.CertificateHeader))
            {
                logger.LogWarning("Removed untrusted client certificate header from peer {RemoteIpAddress}.",
                    context.Connection.RemoteIpAddress);
            }

            await next(context).ConfigureAwait(false);
        });
        return app.UseWhen(context => options.IsTrusted(context.Connection.RemoteIpAddress),
            branch => branch.UseCertificateForwarding());
    }

    private sealed record TrustedCertificateForwardingOptions(
        string CertificateHeader,
        ForwardedHeadersOptions Proxies)
    {
        public bool IsTrusted(IPAddress? address)
        {
            if (address == null)
            {
                return false;
            }

            return Matches(address) || address.IsIPv4MappedToIPv6 && Matches(address.MapToIPv4());
        }

        private bool Matches(IPAddress address) =>
            Proxies.KnownProxies.Contains(address) || Proxies.KnownIPNetworks.Any(network => network.Contains(address));
    }
}
