@mcp-server-authorization
Feature: MCP CA Operation Authorization

The MCP server exposes the CA's most destructive operations: signing certificates
(sign_certificate) and revoking certificates (revoke_certificate). These MUST require an authenticated,
authorized caller and MUST fail closed by default. The authorization routes through the same authorization
intent as the HTTP ca.server layer (authenticated caller for signing; CA-admin role for revocation).

Rule: Unauthenticated callers are rejected (fail closed)

Scenario: An unauthenticated caller cannot sign a certificate
    Given the MCP server has no authenticated caller
    When the MCP server invokes "sign_certificate" with a valid CSR
    Then the result MUST indicate failure
    Then the error message MUST indicate the caller is not authorized

Scenario: An unauthenticated caller cannot revoke a certificate
    Given a certificate is issued by an admin caller
    Given the MCP server has no authenticated caller
    When the MCP server invokes "revoke_certificate" with an issued certificate's serial number
    Then the result MUST indicate failure
    Then the error message MUST indicate the caller is not authorized

Rule: Revoking arbitrary certificates requires the CA-admin role

Scenario: An authenticated caller without the CA-admin role cannot revoke
    Given a certificate is issued by an admin caller
    Given the MCP server has an authenticated caller without the CA-admin role
    When the MCP server invokes "revoke_certificate" with an issued certificate's serial number
    Then the result MUST indicate failure
    Then the error message MUST mention the CA-admin role

Scenario: An authenticated caller without the CA-admin role may still sign
    Given the MCP server has an authenticated caller without the CA-admin role
    When the MCP server invokes "sign_certificate" with a valid CSR
    Then the result MUST succeed

Rule: An authorized caller may perform CA operations

Scenario: An authenticated CA-admin caller may sign and revoke
    Given the MCP server has an authenticated CA-admin caller
    When the MCP server invokes "sign_certificate" with a valid CSR
    When the MCP server invokes "revoke_certificate" with an issued certificate's serial number
    Then the result MUST succeed

Rule: The CA surface fails closed by default

Scenario: CA operations require an authentication token
    Given the MCP server has CA operations enabled
    Given no authentication token is configured
    When the MCP server configuration is validated
    Then startup MUST be refused
    Then the refusal reason MUST mention the authentication token

Scenario: A self-signed test CA requires an explicit opt-in
    Given the MCP server has CA operations enabled
    Given an authentication token is configured
    Given the self-signed test CA is not allowed
    When the MCP server configuration is validated
    Then startup MUST be refused
    Then the refusal reason MUST mention an access-controlled CA

Scenario: A fully configured CA-enabled server starts
    Given the MCP server has CA operations enabled
    Given an authentication token is configured
    Given the self-signed test CA is allowed
    When the MCP server configuration is validated
    Then startup MUST be allowed
