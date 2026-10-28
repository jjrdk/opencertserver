namespace OpenCertServer.Ca.Utils.Validation;

/// <summary>
/// The kind of application-service identifier a TLS/DTLS endpoint may present, as defined by
/// RFC 9525 (obsoletes RFC 6125). Each corresponds to a <c>subjectAltName</c> entry.
/// </summary>
public enum ServiceIdentifierType
{
    /// <summary>A DNS domain name, e.g. <c>www.bigcompany.example</c> (<c>dNSName</c>).</summary>
    Dns,

    /// <summary>An IP address, e.g. <c>192.0.2.107</c> (<c>iPAddress</c>).</summary>
    Ip,

    /// <summary>
    /// A service name per RFC 4985 (the <c>SRVName</c> <c>otherName</c> form),
    /// e.g. <c>_imaps.isp.example</c>.
    /// </summary>
    Srv,

    /// <summary>A URI, e.g. <c>sip:voice.college.example</c> (<c>uniformResourceIdentifier</c>).</summary>
    Uri
}