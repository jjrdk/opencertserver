namespace OpenCertServer.Mcp;

using System.Security.Claims;
using OpenCertServer.Ca.Server;

/// <summary>
/// CA-mutating operations performed through the MCP surface. Read-only operations
/// (CRL / OCSP / query / metadata) are not represented here: they require no
/// authorization at all.
/// </summary>
public enum McpCaOperation
{
    /// <summary>Issue a certificate from a CSR (<c>sign_certificate</c>).</summary>
    Sign,

    /// <summary>Revoke a certificate by serial number (<c>revoke_certificate</c>).</summary>
    Revoke
}

/// <summary>
/// Enforcement point for CA-mutating MCP tools.
/// </summary>
/// <remarks>
/// This is the seam that routes MCP through the same authorization intent as the
/// HTTP <c>ca.server</c> layer (see
/// <see cref="RevocationAuthorizationConstants"/>): signing requires an
/// authenticated caller; revoking requires the CA-admin role. A co-located or
/// co-process caller that has not been authenticated is rejected — the destructive
/// tools fail closed.
/// </remarks>
public interface IMcpAuthorization
{
    /// <summary>
    /// Ensures the caller is permitted to perform <paramref name="operation"/>.
    /// </summary>
    /// <param name="operation">The CA-mutating operation being performed.</param>
    /// <param name="caller">The authenticated caller principal (may be anonymous).</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <exception cref="McpException">
    /// Thrown when the operation is not authorized. Never discloses the configured
    /// secret.
    /// </exception>
    Task EnsureAuthorizedAsync(
        McpCaOperation operation,
        ClaimsPrincipal caller,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether <paramref name="caller"/> is an authenticated (non-anonymous) principal.
    /// </summary>
    bool IsAuthenticated(ClaimsPrincipal caller);
}

/// <summary>
/// Default <see cref="IMcpAuthorization"/> implementation.
/// </summary>
/// <remarks>
/// Reads its policy from <see cref="McpServerOptions"/>. By default
/// <see cref="McpServerOptions.RequireCallerAuthentication"/> is <c>true</c>, so
/// every mutating operation fails closed when the caller is not authenticated.
/// Revocation additionally requires the CA-admin role, matching the admin path of
/// the HTTP <c>ca.server</c> revocation handler.
/// </remarks>
public sealed class DefaultMcpAuthorization : IMcpAuthorization
{
    private readonly McpServerOptions _options;

    /// <summary>
    /// Creates a default authorization enforcing the given options.
    /// </summary>
    public DefaultMcpAuthorization(McpServerOptions options)
    {
        _options = options;
    }

    /// <inheritdoc/>
    public bool IsAuthenticated(ClaimsPrincipal caller)
        => caller is not null && caller.Identity?.IsAuthenticated == true;

    /// <inheritdoc/>
    public Task EnsureAuthorizedAsync(
        McpCaOperation operation,
        ClaimsPrincipal caller,
        CancellationToken cancellationToken = default)
    {
        // Allow only when an operator has explicitly disabled the check. The default
        // is to require authentication, so the destructive tools fail closed.
        if (!_options.RequireCallerAuthentication)
        {
            return Task.CompletedTask;
        }

        if (!IsAuthenticated(caller))
        {
            throw new McpException(
                $"CA operation '{operation}' is not authorized: no authenticated caller is present. " +
                "Configure McpServer:AuthenticationToken so the MCP process authenticates its caller " +
                "before performing certificate operations.");
        }

        if (operation == McpCaOperation.Revoke)
        {
            var requiredRole = string.IsNullOrWhiteSpace(_options.RevocationRole)
                ? RevocationAuthorizationConstants.CaAdminRole
                : _options.RevocationRole;

            if (!IsInRole(caller, requiredRole))
            {
                throw new McpException(
                    $"'revoke_certificate' is not authorized: the caller does not hold the required " +
                    $"role '{requiredRole}'. Revoking arbitrary certificates is restricted to the " +
                    "CA-admin role (matching the ca.server revocation handler).");
            }
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Mirrors <see cref="ClaimsPrincipal.IsInRole"/>: matches both
    /// <see cref="ClaimTypes.Role"/> and a <c>"role"</c> claim, mirroring the
    /// <c>ca.server</c> revocation handler which accepts either.
    /// </summary>
    private static bool IsInRole(ClaimsPrincipal caller, string role)
        => caller.HasClaim(c => c.Value == role && (c.Type == ClaimTypes.Role || c.Type == "role"));
}

/// <summary>
/// Result of validating the CA-operation security configuration.
/// </summary>
public enum McpServerConfigurationResult
{
    /// <summary>CA-mutating tools are disabled and not registered.</summary>
    Disabled,

    /// <summary>CA-mutating tools are registered and authorized callers may use them.</summary>
    Enabled
}

/// <summary>
/// Fail-closed gate for starting a CA-capable MCP server.
/// </summary>
/// <remarks>
/// Implements the three preconditions of security-review F-02:
/// <list type="bullet">
/// <item>CA-mutating tools are off unless <see cref="McpServerOptions.EnableCaOperations"/>.</item>
/// <item>When enabled, an <see cref="McpServerOptions.AuthenticationToken"/> is required.</item>
/// <item>The self-signed "MCP Test CA" is only created when
/// <see cref="McpServerOptions.AllowSelfSignedTestCa"/> is explicitly set, so a bare default
/// invocation never silently starts a forge-capable self-signed CA.</item>
/// </list>
/// </remarks>
public static class McpServerConfiguration
{
    /// <summary>
    /// Whether the CA-mutating tools should be registered.
    /// </summary>
    public static bool ShouldRegisterCaOperations(McpServerOptions options)
        => options.EnableCaOperations;

    /// <summary>
    /// Validates the CA-operation security preconditions.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when CA operations are enabled but a security precondition is not
    /// met (no authenticated caller, or no real CA key configured). This is the
    /// fail-closed behavior that replaces the previous "default self-signed CA."
    /// </exception>
    public static McpServerConfigurationResult EnsureConfigured(McpServerOptions options)
    {
        if (!ShouldRegisterCaOperations(options))
        {
            return McpServerConfigurationResult.Disabled;
        }

        if (string.IsNullOrWhiteSpace(options.AuthenticationToken))
        {
            throw new InvalidOperationException(
                "McpServer:EnableCaOperations is true but McpServer:AuthenticationToken is not set. " +
                "The CA-mutating tools require an authenticated caller; the server will not start " +
                "without one to prevent unauthenticated certificate issuance or revocation.");
        }

        // No external CA-key loader is wired into the MCP host yet, so the only CA key
        // available here is the in-memory self-signed "MCP Test CA", which is dev/test
        // only. Require it to be opted into explicitly so a bare invocation never
        // silently starts a forge-capable self-signed CA.
        if (!options.AllowSelfSignedTestCa)
        {
            throw new InvalidOperationException(
                "McpServer:EnableCaOperations is true but no access-controlled CA key is configured. " +
                "Set McpServer:AllowSelfSignedTestCa only for development/tests, or configure a real, " +
                "access-controlled CA key for production.");
        }

        return McpServerConfigurationResult.Enabled;
    }

    /// <summary>
    /// Builds the authenticated caller principal for a validly configured server.
    /// </summary>
    /// <remarks>
    /// When <see cref="McpServerOptions.AuthenticationToken"/> is empty the result
    /// is an anonymous principal (fail-closed). This primitive is
    /// the authentication boundary: presence of the shared secret authenticates the
    /// process's caller; the <see cref="DefaultMcpAuthorization"/> applies authZ.
    /// </remarks>
    public static ClaimsPrincipal BuildAuthenticatedCaller(McpServerOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.AuthenticationToken))
        {
            return new ClaimsPrincipal();
        }

        var name = string.IsNullOrWhiteSpace(options.CallerName) ? "mcp-caller" : options.CallerName;
        var role = string.IsNullOrWhiteSpace(options.RevocationRole)
            ? RevocationAuthorizationConstants.CaAdminRole
            : options.RevocationRole;

        var identity = new ClaimsIdentity(
            new[]
            {
                new Claim(ClaimTypes.Name, name),
                new Claim(ClaimTypes.Role, role)
            },
            authenticationType: "McpSharedSecret");

        return new ClaimsPrincipal(identity);
    }
}
