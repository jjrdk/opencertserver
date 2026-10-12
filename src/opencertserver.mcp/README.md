# OpenCertServer MCP

This project hosts the OpenCertServer Model Context Protocol (MCP) server. It exposes the certificate and CA capabilities of the platform to MCP clients over stdio, making it possible to query, issue, and revoke certificates through a tool-based interface.

## Functionality
- Starts a stdio-based MCP server using the official `ModelContextProtocol` .NET SDK
- Discovers and registers tools with `[McpServerToolType]` and `[McpServerTool]`
- Exposes certificate-management operations backed by the CA and CA-server layers
- Provides a single protocol surface for MCP-driven certificate administration workflows

## Security / configuration

The two destructive tools, `sign_certificate` and `revoke_certificate`, are gated behind an
authenticated, authorized caller and fail closed by default. Configuration is read from the `McpServer` 
options section, which also accepts `MCP_`-prefixed environment variables (e.g. `MCP_MCPSERVER_EnableCaOperations`).

| Option | Default | Meaning |
|---|---|---|
| `McpServer:EnableCaOperations` | `false` | Registers the destructive `sign_certificate` / `revoke_certificate` tools. When `false`, the server is read-only (CRL / OCSP / query / metadata). |
| `McpServer:RequireCallerAuthentication` | `true` | Every call requires an authenticated caller. Signing mirrors `ca.server`'s authenticated-user requirement; revoking additionally requires the `RevocationRole`. |
| `McpServer:AuthenticationToken` | *(unset)* | Shared secret that authenticates the process's caller. Required when `EnableCaOperations` is `true`; the server refuses to start without it. Never written to logs or returned in tool output. |
| `McpServer:CallerName` | `mcp-caller` | Friendly identity of the authenticated caller principal. |
| `McpServer:RevocationRole` | `ca_admin` | Role required to revoke arbitrary certificates. Defaults to `RevocationAuthorizationConstants.CaAdminRole`, matching the HTTP `ca.server` revocation handler. |
| `McpServer:AllowSelfSignedTestCa` | `false` | Permits the in-memory, self-signed "MCP Test CA" — for development and tests only. When CA operations are enabled, the server refuses to start unless this is set or a real, access-controlled CA key is configured. |

The start gate (`McpServerConfiguration.EnsureConfigured` in `McpAuthorization.cs`) runs before the
host starts and throws if CA operations are enabled without a token, or without an opted-in CA key.
Read-only tools require no configuration and are always available. See
`docs/standards.md → MCP server` for the full authorization model and the
`McpServerAuthorization.feature` regression tests.

## Dependencies
- `ModelContextProtocol` package for the MCP server runtime
- `opencertserver.ca` for certificate authority logic
- `opencertserver.ca.utils` for shared PKI helpers
- `opencertserver.ca.server` for the server-side CA implementation

This project is an integration layer that exposes existing OpenCertServer functionality through the MCP protocol rather than implementing certificate logic on its own.
