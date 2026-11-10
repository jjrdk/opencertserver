namespace OpenCertServer.Acme.Server.Services;

using System;
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
/// <item>Connecting only to the address set corroborated by the DNS Network Perspectives, when one is pinned on the request.</item>
/// <item>Resolving the target hostname exactly once at connection time when no address set is pinned (prevents DNS rebinding).</item>
/// <item>Rejecting connections whose actual target IP falls in any prohibited address range.</item>
/// <item>Disabling automatic redirect following (prevents redirect-to-internal bypass).</item>
/// <item>Disabling the system proxy so the connection target is always the challenge host.</item>
/// <item>Disabling connection reuse so every request connects to its own corroborated address set.</item>
/// </list>
/// </summary>
internal static class SsrfBlockingSocketsHandler
{
    /// <summary>
    /// Request option that carries the A/AAAA address set corroborated by the DNS Network Perspectives.
    /// </summary>
    internal static readonly HttpRequestOptionsKey<IReadOnlyList<IPAddress>> CorroboratedAddressesKey =
        new("OpenCertServer.Acme.CorroboratedAddresses");

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
            UseProxy = false,
            // Never reuse a connection established under an earlier DNS answer; every
            // challenge request must connect to its own corroborated address set.
            PooledConnectionLifetime = TimeSpan.Zero,
            ConnectCallback = ConnectWithValidationAsync
        };

    /// <summary>
    /// Pins the request to the address set that the DNS Network Perspectives corroborated.
    /// The connection handler will only connect to these addresses and will re-check each
    /// target against <see cref="ProhibitedRanges"/> before opening a socket.
    /// </summary>
    internal static void PinToCorroboratedAddresses(
        HttpRequestMessage request,
        IReadOnlyList<IPAddress> addresses)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(addresses);

        request.Options.Set(CorroboratedAddressesKey, addresses);
    }

    /// <summary>
    /// Selects the first connection target that is not in a prohibited range.
    /// </summary>
    internal static IPAddress SelectAllowedAddress(
        IEnumerable<IPAddress> addresses,
        string host)
    {
        foreach (var address in addresses)
        {
            if (!IsProhibited(address))
            {
                return address;
            }
        }

        throw new HttpRequestException(
            $"Connection rejected: all connection targets for '{host}' are in prohibited ranges.");
    }

    private static bool IsProhibited(IPAddress address)
    {
        foreach (var range in ProhibitedRanges)
        {
            if (range.Contains(address))
            {
                return true;
            }
        }

        return false;
    }

    private static async ValueTask<Stream> ConnectWithValidationAsync(
        SocketsHttpConnectionContext context,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<IPAddress> addresses;
        if (context.InitialRequestMessage.Options.TryGetValue(
                CorroboratedAddressesKey,
                out var corroboratedAddresses))
        {
            // Never fall back to ambient DNS when the validator has pinned a corroborated set.
            addresses = corroboratedAddresses;
        }
        else
        {
            addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken)
                .ConfigureAwait(false);
        }

        // Re-check the actual connection targets so a pinned set can never reach a prohibited range.
        var allowedIp = SelectAllowedAddress(addresses, context.DnsEndPoint.Host);

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
