namespace OpenCertServer.Est.Server.BasicAuthentication;

using Microsoft.AspNetCore.Authentication;
using OpenCertServer.Ca.Utils;

/// <summary>
/// Options for the EST Basic authentication: who may enroll with a user name and password. Empty
/// means off - the handler accepts nothing and offers no challenge.
/// </summary>
public sealed class EstBasicAuthenticationOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Users by name, the value being the password hash from <see cref="PasswordHash.Create"/>. In
    /// configuration: <c>Est:BasicAuth:Users:&lt;name&gt;</c>.
    /// </summary>
    public Dictionary<string, string> Users { get; set; } = new(StringComparer.Ordinal);

    /// <summary>
    /// A file with one <c>name:hash</c> per line (<c>#</c> starts a comment), read again whenever it
    /// changes - the htpasswd shape, for a secret that should not sit in an environment variable. In
    /// configuration: <c>Est:BasicAuth:UsersFile</c>.
    /// </summary>
    public string? UsersFile { get; set; }

    /// <summary>The realm offered in the challenge.</summary>
    public string Realm { get; set; } = EstBasicAuthenticationDefaults.Realm;
}
