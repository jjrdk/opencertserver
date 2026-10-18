@iq @blackbox @linux-client @hardened
Feature: The MCP server exposes the CA over stdio and fails closed
  OpenCertServer's MCP server is a stdio (JSON-RPC) tool interface to the CA, used by
  AI agents, started as a subprocess from a Linux client. These scenarios verify the
  tool surface is present and, critically, that the two destructive tools
  (`sign_certificate`, `revoke_certificate`) fail closed unless the operator has opted
  in and supplied an authentication token.

  They complement the in-process MCP suite; the new assertion is that the server,
  *launched as a subprocess on a Linux host*, reports and gates its tools as it should.

  Rule: Read-only tools are always available
  Scenario: The MCP server advertises its tools
    Given the Linux client launches the MCP server over stdio in read-only mode
    And the Linux client sends a "tools/list" JSON-RPC request on stdin
    Then the response lists the CA tools including "get_server_metadata" and "get_crl"

  Scenario: A read-only query returns live data
    Given the Linux client launches the MCP server with CA operations enabled and a configured "McpServer:AuthenticationToken"
    When the Linux client invokes "get_crl" via JSON-RPC
    Then the response carries a CRL

  Rule: Destructive tools fail closed by default
  Scenario: With CA operations disabled the destructive tools are not registered
    Given the Linux client launches the MCP server with "McpServer:EnableCaOperations" = false
    When the Linux client invokes "sign_certificate" via JSON-RPC
    Then the JSON-RPC result is an error with code -32602 ("unknown tool")

  Scenario: Enabling CA operations without a token refuses to start
    Given the Linux client launches the MCP server with "McpServer:EnableCaOperations" = true and no "McpServer:AuthenticationToken"
    Then the process refuses to start and reports that an authentication token is required

  Scenario: With a token and CA enabled, signing is available
    Given the Linux client launches the MCP server with CA operations enabled and a configured "McpServer:AuthenticationToken"
    When the Linux client invokes "sign_certificate" with a valid CSR via JSON-RPC
    Then the response contains a signed certificate
