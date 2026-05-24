namespace OpenCertServer.Mcp;

using OpenCertServer.Mcp.Tools;

/// <summary>
/// Helper class to register all MCP tools with the server.
/// Call this after creating the McpServer and before starting it.
/// </summary>
public static class RegisterTools
{
     /// <summary>
     /// Registers all available CA MCP tools with the given server instance.
     /// </summary>
    public static McpServer RegisterAll(this McpServer server)
     {
          // Certificate query tools
        server.RegisterTool(GetServerMetadataTool.Create());
        server.RegisterTool(ListCertificatesTool.Create());
        server.RegisterTool(SearchCertificatesTool.Create());
        server.RegisterTool(GetCertificateTool.Create());
        server.RegisterTool(GetCaCertificatesTool.Create());

         // Certificate operations tools
        server.RegisterTool(SignCertificateTool.Create());
        server.RegisterTool(RevokeCertificateTool.Create());

         // Revocation checking tools
        server.RegisterTool(GetRevocationStatusTool.Create());
        server.RegisterTool(CheckOcspStatusTool.Create());
        server.RegisterTool(GetCrlTool.Create());

        return server;
     }
}
