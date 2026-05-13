@mcp-server-metadata
Feature: MCP Server Metadata

    The get_server_metadata tool MUST return a consistent snapshot of CA
    server configuration including profile information, supported cryptographic
    primitives, OCSP/CRL URLs, and EST endpoint paths.

    Scenario: Server returns metadata with required fields
        When the MCP server invokes "get_server_metadata" with no parameters
        Then the result MUST succeed
        And the response MUST include a server name
        And the response MUST include a server version string
        And the response MUST include a list of CA profiles
        And the response MUST include OCSP URLs
        And the response MUST include CRL URLs
        And the response MUST include CA Issuers URLs
        And the response MUST include EST endpoint URLs
        And the response MUST include supported key types
        And the response MUST include supported signature algorithms

    Scenario: Each CA profile includes chain and key information
        When the MCP server invokes "get_server_metadata"
        Then the result MUST succeed
        And each CA profile MUST have a name
        And each CA profile MUST have a certificate chain
        And each CA profile MUST indicate whether it has a private key
        And each CA profile MUST have a certificate validity period in days
        And each CA profile MUST indicate whether it has an OCSP signing key
        And each CA profile MUST include the OCSP freshness window as a string

    Scenario: Supported key types include RSA and ECDSA
        When the MCP server invokes "get_server_metadata"
        Then the result MUST succeed
        And the supported key types MUST include "RSA"
        And the supported key types MUST include "ECDSA"

    Scenario: Supported signature algorithms include all listed
        When the MCP server invokes "get_server_metadata"
        Then the result MUST succeed
        And the supported signature algorithms MUST include "SHA256withRSA"
        And the supported signature algorithms MUST include "SHA256withECDSA"
        And the supported signature algorithms MUST include "SHA512withRSA"
        And the supported signature algorithms MUST include "SHA512withECDSA"

    Scenario: EST endpoint URLs use the standard path prefix
        When the MCP server invokes "get_server_metadata"
        Then the result MUST succeed
        And the caBundle endpoint MUST start with "/.well-known/est"
        And the simpleEnroll endpoint MUST be "/.well-known/est/simpleenroll"
        And the simpleReenroll endpoint MUST be "/.well-known/est/simplereenroll"

    Scenario: CSR key size constraints are reported
        When the MCP server invokes "get_server_metadata"
        Then the result MUST succeed
        And the reported max CSR key size MUST be at least 2048
        And the reported min CSR key size MUST be at least 2048
        And min MUST be less than or equal to max
