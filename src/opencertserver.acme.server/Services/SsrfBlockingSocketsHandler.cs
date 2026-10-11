namespace OpenCertServer.Acme.Server.Services;

using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// A <see cref="SocketsHttpHandler"/> that prevents Server-Side Request Forgery (SSRF) by:
/// <list type="bullet">
/// <item>Resolving the target hostname exactly once at connection time (prevents DNS rebinding).</item>
/// <item>Rejecting connections whose resolved IP falls in any prohibited address range.</item>
/// <item>Disabling automatic redirect following (prevents redirect-to-internal bypass).</item>
/// </list>
/// </summary>
internal static class SsrfBlockingSocketsHandler
{
    /// <summary>
    /// Address ranges that must never be contacted by the http-01 challenge fetcher.
    /// </summary>
    internal static readonly IReadOnlyList<IPNetwork> ProhibitedRanges =
    [
        IPNetwork.Parse("0.0.0.0/8"),      // IPv4 "this host" (0.0.0.0 reaches loopback on Linux)
        IPNetwork.Parse("127.0.0.0/8"),    // IPv4 loopback
        IPNetwork.Parse("::/128"),          // IPv6 unspecified (reaches loopback on Linux)
        IPNetwork.Parse("::1/128"),         // IPv6 loopback
        IPNetwork.Parse("169.254.0.0/16"), // IPv4 link-local (includes cloud metadata)
        IPNetwork.Parse("fe80::/10"),       // IPv6 link-local
        IPNetwork.Parse("10.0.0.0/8"),     // RFC1918 private
        IPNetwork.Parse("172.16.0.0/12"),  // RFC1918 private
        IPNetwork.Parse("192.168.0.0/16"), // RFC1918 private
        IPNetwork.Parse("100.64.0.0/10"),  // CGNAT shared address space
        IPNetwork.Parse("fc00::/7"),        // IPv6 unique-local (ULA)
    ];

    /// <summary>
    /// Creates a new <see cref="SocketsHttpHandler"/> configured for SSRF-safe challenge fetches.
    /// </summary>
    internal static SocketsHttpHandler Create() =>
        new()
        {
            AllowAutoRedirect = false,
            ConnectCallback = ConnectWithValidationAsync
        };

    private static async ValueTask<Stream> ConnectWithValidationAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken)
            .ConfigureAwait(false);

        IPAddress? allowedIp = null;
        foreach (var address in addresses)
        {
            var blocked = false;
            foreach (var range in ProhibitedRanges)
            {
                if (range.Contains(address))
                {
                    blocked = true;
                    break;
                }
            }

            if (!blocked)
            {
                allowedIp = address;
                break;
            }
        }

        if (allowedIp is null)
        {
            throw new HttpRequestException(
                $"Connection rejected: all resolved addresses for '{context.DnsEndPoint.Host}' are in prohibited ranges.");
        }

        var socket = new Socket(allowedIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };

        try
        {
            await socket.ConnectAsync(
                    new IPEndPoint(allowedIp, context.DnsEndPoint.Port),
                    cancellationToken)
                .ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
