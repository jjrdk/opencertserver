namespace OpenCertServer.Mcp;

/// <summary>
/// Represents error types returned by MCP tools.
/// Mirrors MCP specification error codes.
/// </summary>
public enum McpErrorCode
{
     /// <summary>
     /// This is the default error code. It is used when a more specific code is not available.
     /// </summary>
    ParseError = -32700,

     /// <summary>
     /// The server received an invalid JSON-RPC request.
     /// </summary>
    InvalidRequest = -32600,

     /// <summary>
     /// The server does not support (know how to handle) this tool.
     /// </summary>
    ToolNotFound = -32601,

     /// <summary>
     /// The server encountered an unexpected error while processing the tool call.
     /// </summary>
    InternalError = -32603,

     /// <summary>
     /// The client sent a required parameter that is missing.
     /// </summary>
    InvalidParams = -32602,

     /// <summary>
     /// The CA certificate store could not be found.
     /// </summary>
    CertificateStoreNotFound = -32001,

     /// <summary>
     /// A certificate resource was not found in the store.
     /// </summary>
    CertificateNotFound = -32002,

     /// <summary>
     /// The certificate could not be revoked (e.g., invalid serial number).
     /// </summary>
    CertificateRevocationFailed = -32003,

     /// <summary>
     /// The CA certificate request could not be signed.
     /// </summary>
    CertificateSigningFailed = -32004,

     /// <summary>
     /// The CA profile was not found.
     /// </summary>
    ProfileNotFound = -32005
}
