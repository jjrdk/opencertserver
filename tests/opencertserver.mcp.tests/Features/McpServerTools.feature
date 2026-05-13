@mcp-server-tools
Feature: MCP Server Tool Registration

    The MCP server MUST register and expose the expected set of certificate authority tools.
    Each tool MUST have a unique name, a non-empty description, and a valid JSON Schema input schema.

    Scenario: Server starts and registers all tools
        When the MCP server initializes
        Then all tools MUST be registered successfully
        And the server MUST report exactly 10 registered tools

    Scenario Outline: Each registered tool has valid metadata
        When the MCP server lists tool "<toolName>"
        Then the tool definition MUST exist
        And it MUST have a non-empty name "<toolName>"
        And it MUST have a non-empty description
        And it MUST have a valid JSON Schema input schema

        Examples:
            | toolName                         |
            | get_server_metadata              |
            | list_certificates                |
            | search_certificates              |
            | get_certificate                  |
            | get_ca_certificates              |
            | sign_certificate                 |
            | revoke_certificate               |
            | get_revocation_status            |
            | check_ocsp_status                |
            | get_crl                           |

    Scenario: Calling a non-existent tool returns ToolNotFound
        When the MCP server attempts to invoke a non-existent tool
        Then the result MUST indicate failure
        And the error code MUST be McpErrorCode.ToolNotFound (1001)
