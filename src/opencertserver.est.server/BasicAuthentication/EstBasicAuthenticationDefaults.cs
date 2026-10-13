namespace OpenCertServer.Est.Server.BasicAuthentication;

/// <summary>Names for the HTTP Basic authentication scheme of the EST server (RFC 7030 §3.2.3).</summary>
public static class EstBasicAuthenticationDefaults
{
    /// <summary>The scheme name, as it appears in the Authorization and WWW-Authenticate headers.</summary>
    public const string AuthenticationScheme = "Basic";

    /// <summary>The realm offered in the challenge. It says nothing about which credentials are meant.</summary>
    public const string Realm = "EST";
}
