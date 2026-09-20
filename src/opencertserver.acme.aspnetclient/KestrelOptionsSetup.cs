using OpenCertServer.Acme.Abstractions.AcmeRoute;

namespace OpenCertServer.Acme.AspNetClient;

using Certes;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

internal sealed partial class KestrelOptionsSetup : IConfigureOptions<KestrelServerOptions>
{
    private readonly IAcmeRenewalService _renewalService;
    private readonly AcmeRouteScope _routeScope;
    private readonly IAcmeRouteConfigurationSource _routeConfigurationSource;
    private readonly ILogger<KestrelOptionsSetup> _logger;

    private volatile IReadOnlyDictionary<string, string>? _cachedHostIndex;
    private readonly Lock _indexLock = new();

    public KestrelOptionsSetup(
        IAcmeRenewalService renewalService,
        AcmeRouteScope routeScope,
        IAcmeRouteConfigurationSource routeConfigurationSource,
        ILogger<KestrelOptionsSetup> logger)
    {
        _renewalService = renewalService;
        _routeScope = routeScope;
        _routeConfigurationSource = routeConfigurationSource;
        _logger = logger;
    }

    public void Configure(KestrelServerOptions options)
    {
        options.ConfigureHttpsDefaults(o =>
        {
            o.ServerCertificateSelector = (_, hostName) => SelectCertificateFor(hostName);
        });
    }

    /// <summary>
    /// The SNI selection logic used by <see cref="Configure"/>. Given an incoming SNI host
    /// name it returns the leaf for the ACME route whose hosts contain that host, falling back
    /// to the renewal service's current leaf and then to the default-route leaf. Extracted so
    /// the selection behaviour can be verified without binding a Kestrel listener.
    /// </summary>
    internal X509Certificate2? SelectCertificateFor(string? hostName)
    {
        var hostToRouteId = GetHostIndex();

        return SelectCertificate(hostName, hostToRouteId)
         ?? _renewalService.Certificate
         ?? _routeScope.GetCertificate(AcmeRouteConstants.DefaultRouteId);
    }

    private IReadOnlyDictionary<string, string> GetHostIndex()
    {
        if (_cachedHostIndex != null)
        {
            return _cachedHostIndex;
        }

        lock (_indexLock)
        {
            if (_cachedHostIndex != null)
            {
                return _cachedHostIndex;
            }

            _cachedHostIndex = BuildHostIndex();
        }

        return _cachedHostIndex;
    }

    private X509Certificate2? SelectCertificate(string? hostName, IReadOnlyDictionary<string, string> hostToRouteId)
    {
        if (string.IsNullOrEmpty(hostName))
        {
            return null;
        }

        if (hostToRouteId.TryGetValue(hostName, out var routeId))
        {
            var cert = _routeScope.GetCertificate(routeId);
            if (cert != null)
            {
                return cert;
            }

            LogNoCertificateIsAvailableYetForRouteRouteidMatchingSniHostHost(routeId, hostName);
            return _routeScope.GetCertificate(AcmeRouteConstants.DefaultRouteId);
        }

        // SNI host not in any ACME route -> fall back to the default leaf and warn.
        LogNoAcmeRouteMatchesSniHostHostServingDefaultCertificate(hostName);
        return _routeScope.GetCertificate(AcmeRouteConstants.DefaultRouteId);
    }

    private IReadOnlyDictionary<string, string> BuildHostIndex()
    {
        var index = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var route in _routeConfigurationSource.GetRouteConfigurations())
        {
            foreach (var host in route.Hosts)
            {
                index[host] = route.RouteId;
            }
        }

        return index;
    }

    [LoggerMessage(LogLevel.Warning, "No certificate is available yet for route {RouteId} matching SNI host {Host}")]
    partial void LogNoCertificateIsAvailableYetForRouteRouteidMatchingSniHostHost(string routeId, string host);

    [LoggerMessage(LogLevel.Warning, "No ACME route matches SNI host {Host}; serving default certificate")]
    partial void LogNoAcmeRouteMatchesSniHostHostServingDefaultCertificate(string host);
}
