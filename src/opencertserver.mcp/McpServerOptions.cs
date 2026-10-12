namespace OpenCertServer.Mcp;

using OpenCertServer.Ca.Server;

/// <summary>
/// Configuration options for the MCP (Model Context Protocol) certificate authority server.
/// </summary>
public class McpServerOptions
{
    /// <summary>
    /// Name of the MCP server. Shown to MCP clients for identification.
    /// </summary>
    public string ServerName { get; set; } = "OpenCertServer CA";

    /// <summary>
    /// Version string following semver convention.
    /// </summary>
    public string ServerVersion { get; set; } = "3.1.0";

    /// <summary>
    /// When true, the MCP server lists all available tools and their descriptions.
    /// Defaults to true.
    /// </summary>
    public bool ListToolsOnStart { get; set; } = true;

    /// <summary>
    /// When true, the MCP server enables structured logging and telemetry for tool invocations.
    /// Defaults to true.
    /// </summary>
    public bool EnableTelemetry { get; set; } = true;

    // ------------------------------------------------------------------
    // The MCP surface exposes the CA's most
    // destructive operations (issuing and revoking certificates). Every
    // one of them is opt-in and fails closed by default.
    // ------------------------------------------------------------------

    /// <summary>
    /// Whether the CA-mutating tools (<c>sign_certificate</c> and
    /// <c>revoke_certificate</c>) are registered and usable.
    /// </summary>
    /// <remarks>
    /// Defaults to <c>false</c>. The server therefore starts as a read-only MCP
    /// (CRL / OCSP / query / metadata) so that a co-located or co-process
    /// cannot forge or revoke certificates without an explicit operator opt-in.
    /// When <c>true</c> the server additionally requires
    /// <see cref="AuthenticationToken"/> to be configured, otherwise it refuses to start.
    /// </remarks>
    public bool EnableCaOperations { get; set; } = false;

    /// <summary>
    /// When <c>true</c>, every CA-mutating tool invocation requires an authenticated,
    /// authorized caller (see <see cref="IMcpAuthorization"/>).
    /// </summary>
    /// <remarks>
    /// Defaults to <c>true</c> so that the destructive tools fail closed. Set to
    /// <c>false</c> only with a clear understanding that any able to pipe to the
    /// server can then issue or revoke certificates.
    /// </remarks>
    public bool RequireCallerAuthentication { get; set; } = true;

    /// <summary>
    /// Shared secret used to authenticate the caller to perform CA mutations.
    /// Must be non-empty when <see cref="EnableCaOperations"/> is <c>true</c>.
    /// Never written to logs or returned in tool output.
    /// </summary>
    public string? AuthenticationToken { get; set; }

    /// <summary>
    /// Friendly name of the authenticated caller principal.
    /// </summary>
    public string CallerName { get; set; } = "mcp-caller";

    /// <summary>
    /// The role required to revoke <b>any</b> certificate, providing defense in depth
    /// against mass revocation. Mirrors the HTTP <c>ca.server</c> layer via
    /// <see cref="RevocationAuthorizationConstants.CaAdminRole"/>.
    /// </summary>
    public string RevocationRole { get; set; } = RevocationAuthorizationConstants.CaAdminRole;

    /// <summary>
    /// Whether the in-memory, self-signed "MCP Test CA" may be created when a CA is
    /// enabled but no external key is configured.
    /// </summary>
    /// <remarks>
    /// Defaults to <c>false</c>. A self-signed CA is acceptable for development and
    /// tests only; in production the CA key must be the real, access-controlled one.
    /// When CA operations are enabled and no CA is otherwise configured, the server
    /// refuses to start unless this is explicitly set to <c>true</c>.
    /// </remarks>
    public bool AllowSelfSignedTestCa { get; set; } = false;
}
