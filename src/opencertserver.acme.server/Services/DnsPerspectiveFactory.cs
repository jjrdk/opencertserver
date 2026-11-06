namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using Configuration;
using DnsClientX;

/// <summary>
/// Builds the configured DNS Network Perspectives used for Multi-Perspective
/// Issuance Corroboration.
/// </summary>
public static class DnsPerspectiveFactory
{
    /// <summary>
    /// Creates one perspective per configured DoH server. When no explicit list
    /// is configured the legacy single <see cref="AcmeServerOptions.DnsEndpoint"/>
    /// is used, preserving existing deployments.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a configured entry is empty, is not an absolute URL, or is not
    /// a recognised <see cref="DnsEndpoint"/> name. Invalid configuration fails
    /// closed rather than silently disabling corroboration.
    /// </exception>
    public static IReadOnlyList<DnsPerspective> Create(
        AcmeServerOptions options,
        int timeoutMilliseconds)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.DohServers is not { Length: > 0 })
        {
            return
            [
                new DnsPerspective(
                    options.DnsEndpoint.ToString(),
                    new DnsClientXResolver(CreateClient(options.DnsEndpoint, timeoutMilliseconds)))
            ];
        }

        var perspectives = new List<DnsPerspective>(options.DohServers.Length);
        foreach (var entry in options.DohServers)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                throw new InvalidOperationException(
                    "AcmeServer:DohServers must not contain empty entries.");
            }

            var server = entry.Trim();
            perspectives.Add(new DnsPerspective(
                server,
                new DnsClientXResolver(CreateClient(server, timeoutMilliseconds))));
        }

        return perspectives;
    }

    private static ClientX CreateClient(DnsEndpoint endpoint, int timeoutMilliseconds)
        => new(
            endpoint,
            timeOutMilliseconds: timeoutMilliseconds,
            enableCache: false);

    private static ClientX CreateClient(string server, int timeoutMilliseconds)
    {
        if (Uri.TryCreate(server, UriKind.Absolute, out var uri))
        {
            if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"AcmeServer:DohServers entry '{server}' must use the https scheme.");
            }

            return new ClientX(
                uri,
                DnsRequestFormat.DnsOverHttps,
                timeOutMilliseconds: timeoutMilliseconds,
                enableCache: false);
        }

        if (Enum.TryParse<DnsEndpoint>(server, ignoreCase: true, out var endpoint))
        {
            return CreateClient(endpoint, timeoutMilliseconds);
        }

        throw new InvalidOperationException(
            $"AcmeServer:DohServers entry '{server}' is neither an absolute DoH URL "
            + "nor a recognised DnsEndpoint name.");
    }
}
