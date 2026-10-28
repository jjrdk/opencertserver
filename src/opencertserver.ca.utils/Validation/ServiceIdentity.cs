namespace OpenCertServer.Ca.Utils.Validation;

/// <summary>
/// A single application-service identifier as expressed in a certificate's
/// <c>subjectAltName</c> extension, per RFC 9525 §4.
///
/// <para>
/// The <see cref="Type"/> determines how matching is performed (see <see cref="IdentityMatcher"/>):
/// DNS identifiers are compared label-by-label, case-insensitively, with the single left-most
/// wildcard; IP identifiers are compared octet-for-octet; and SRV/URI identifiers are matched by
/// combining their application service type (or URI scheme) with their own DNS name. Matching is
/// always type-specific — a reference of one type can never match a presented identifier of another.
/// </para>
/// </summary>
/// <param name="Type">The identifier type.</param>
/// <param name="Value">
/// The canonical string form for the <see cref="Type"/>: the host for <see cref="ServiceIdentifierType.Dns"/>,
/// the dotted/hex address string for <see cref="ServiceIdentifierType.Ip"/>, the <c>SRVName</c> for
/// <see cref="ServiceIdentifierType.Srv"/>, and the full URI for <see cref="ServiceIdentifierType.Uri"/>.
/// </param>
public sealed record ServiceIdentity(ServiceIdentifierType Type, string Value)
{
    /// <summary>Creates a DNS identifier, e.g. <c>ServiceIdentity.Dns("web.example.com")</c>.</summary>
    public static ServiceIdentity Dns(string host) =>
        new(ServiceIdentifierType.Dns, host);

    /// <summary>Creates an IP identifier from a canonical address string, e.g. <c>192.0.2.107</c> or <c>2001:db8::abcd</c>.</summary>
    public static ServiceIdentity Ip(string address) =>
        new(ServiceIdentifierType.Ip, address);

    /// <summary>Creates an SRV identifier, e.g. <c>_imaps.isp.example</c>.</summary>
    public static ServiceIdentity Srv(string srvName) =>
        new(ServiceIdentifierType.Srv, srvName);

    /// <summary>Creates a URI identifier, e.g. <c>sip:voice.college.example</c>.</summary>
    public static ServiceIdentity Uri(string uri) =>
        new(ServiceIdentifierType.Uri, uri);

    /// <summary>A string representation of the form <c>Type:Value</c>.</summary>
    public override string ToString() => $"{Type}:{Value}";
}
