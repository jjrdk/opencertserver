namespace OpenCertServer.Est.Server.BasicAuthentication;

using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenCertServer.Ca.Utils;

/// <summary>
/// HTTP Basic authentication for the EST endpoints (RFC 7030 §3.2.3): a user name and a password,
/// carried in the Authorization header over TLS. The identity it produces is the user name
/// (<see cref="ClaimTypes.Name"/> and <c>sub</c>), so a server that binds the request to the identity
/// issues to that name only.
/// </summary>
/// <remarks>
/// A password is the weaker credential - whoever has it, has it - so this scheme is off unless users
/// are configured, and then it is the host's choice whether to offer it next to certificates and
/// tokens. Only the user name is logged, never the password.
/// </remarks>
public sealed partial class EstBasicAuthenticationHandler : AuthenticationHandler<EstBasicAuthenticationOptions>
{
    private UsersFileCache? _usersFile;

    public EstBasicAuthenticationHandler(
        IOptionsMonitor<EstBasicAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    /// <inheritdoc />
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // No header is not a refusal, it is "not mine": certificates and tokens run next to this.
        if (!Request.Headers.TryGetValue("Authorization", out var raw)
         || !AuthenticationHeaderValue.TryParse(raw.ToString(), out var header)
         || !string.Equals(header.Scheme, EstBasicAuthenticationDefaults.AuthenticationScheme, StringComparison.OrdinalIgnoreCase)
         || string.IsNullOrEmpty(header.Parameter))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var users = CurrentUsers();
        if (users.Count == 0)
        {
            LogPasswordWayIsOff(Logger);
            return Task.FromResult(AuthenticateResult.Fail("Basic authentication is not configured."));
        }

        string userName, password;
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header.Parameter));
            var colon = decoded.IndexOf(':');
            if (colon < 0)
            {
                return Task.FromResult(AuthenticateResult.Fail("The Basic credentials carry no ':'."));
            }

            userName = decoded[..colon];
            password = decoded[(colon + 1)..];
        }
        catch (FormatException)
        {
            return Task.FromResult(AuthenticateResult.Fail("The Basic credentials are not base64."));
        }

        // An unknown user is verified against nothing, so the time taken does not say whether the name exists.
        var known = users.TryGetValue(userName, out var hash);
        if (!PasswordHash.Verify(password, hash) || !known)
        {
            LogRefused(Logger, userName);
            return Task.FromResult(AuthenticateResult.Fail("User name or password is wrong."));
        }

        LogAuthenticated(Logger, userName);
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, userName), new Claim("sub", userName)],
            Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
    }

    /// <summary>
    /// The challenge names the scheme - some clients send credentials only when asked - but only when
    /// users are configured; an invitation to something that is not there would be worse than none.
    /// </summary>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        if (CurrentUsers().Count > 0)
        {
            Response.Headers.Append("WWW-Authenticate",
                $"{EstBasicAuthenticationDefaults.AuthenticationScheme} realm=\"{Options.Realm}\"");
        }

        return Task.CompletedTask;
    }

    private IReadOnlyDictionary<string, string> CurrentUsers()
    {
        if (string.IsNullOrWhiteSpace(Options.UsersFile))
        {
            return Options.Users;
        }

        _usersFile ??= new UsersFileCache(Options.UsersFile);
        var fromFile = _usersFile.Read(Logger);
        if (Options.Users.Count == 0)
        {
            return fromFile;
        }

        var merged = new Dictionary<string, string>(Options.Users, StringComparer.Ordinal);
        foreach (var (name, hash) in fromFile)
        {
            merged[name] = hash;
        }

        return merged;
    }

    [LoggerMessage(LogLevel.Warning, "Basic credentials were offered, but no users are configured - the password way is off")]
    private static partial void LogPasswordWayIsOff(ILogger logger);

    [LoggerMessage(LogLevel.Warning, "Basic authentication refused for user {UserName}")]
    private static partial void LogRefused(ILogger logger, string userName);

    [LoggerMessage(LogLevel.Information, "Basic authentication succeeded for user {UserName}")]
    private static partial void LogAuthenticated(ILogger logger, string userName);

    /// <summary>The users file, read again when its timestamp changes.</summary>
    private sealed class UsersFileCache(string path)
    {
        private readonly Lock _lock = new();
        private DateTime _readAt = DateTime.MinValue;
        private bool _unreadable;
        private Dictionary<string, string> _users = new(StringComparer.Ordinal);

        public IReadOnlyDictionary<string, string> Read(ILogger logger)
        {
            lock (_lock)
            {
                var info = new FileInfo(path);
                if (!info.Exists)
                {
                    if (_users.Count > 0 || _readAt == DateTime.MinValue)
                    {
                        logger.LogWarning("The Basic users file {Path} does not exist", path);
                    }

                    _users = new Dictionary<string, string>(StringComparer.Ordinal);
                    _readAt = DateTime.UtcNow;
                    _unreadable = false;
                    return _users;
                }

                if (info.LastWriteTimeUtc <= _readAt)
                {
                    return _users;
                }

                // A file that exists but cannot be read (wrong owner or mode, or a directory in its
                // place) must not take the handler down: without this, every request ended in a
                // 401 with a stack trace in the log and no line naming the file. It is said once,
                // and the password way is off until the file changes.
                string[] lines;
                try
                {
                    lines = File.ReadAllLines(path);
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                {
                    if (!_unreadable)
                    {
                        logger.LogError("The Basic users file {Path} cannot be read: {Reason}", path, e.Message);
                    }

                    _unreadable = true;
                    _users = new Dictionary<string, string>(StringComparer.Ordinal);
                    _readAt = info.LastWriteTimeUtc;
                    return _users;
                }

                _unreadable = false;
                var users = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (trimmed.Length == 0 || trimmed[0] == '#')
                    {
                        continue;
                    }

                    var colon = trimmed.IndexOf(':');
                    if (colon <= 0)
                    {
                        logger.LogWarning("The Basic users file {Path} has a line without name:hash", path);
                        continue;
                    }

                    users[trimmed[..colon]] = trimmed[(colon + 1)..];
                }

                _users = users;
                _readAt = info.LastWriteTimeUtc;
                return _users;
            }
        }
    }
}
