namespace OpenCertServer.Acme.Server.Services;

using DnsClientX;

/// <summary>
/// Thrown when DNS responses from two or more Network Perspectives disagree.
/// </summary>
/// <remarks>
/// Per CA/Browser Forum TLS Baseline Requirements §3.2.2.9, a CA must not act on
/// a domain validation or CAA determination unless the relied-upon perspectives
/// provide corroborating information.  This exception deliberately derives from
/// <see cref="DnsClientException"/> so existing fail-closed challenge validation
/// paths treat a disagreement as a DNS failure.
/// </remarks>
public sealed class DnsPerspectiveMismatchException : DnsClientException
{
    public DnsPerspectiveMismatchException(string message, IReadOnlyList<string> perspectives)
        : base(message)
    {
        Perspectives = perspectives;
    }

    /// <summary>
    /// Gets the names of all Network Perspectives that contributed to the lookup.
    /// </summary>
    public IReadOnlyList<string> Perspectives { get; }
}
