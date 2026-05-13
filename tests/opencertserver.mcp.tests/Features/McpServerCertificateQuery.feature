@mcp-server-certificate-query
@mcp-get-certificate
@mcp-list-certificates
@mcp-search-certificates
@mcp-get-ca-certificates
Feature: MCP Certificate Query Tools

    This feature covers the certificate query tools: list_certificates, search_certificates,
    get_certificate, and get_ca_certificates. These tools allow clients to discover and inspect
    certificates managed by the CA.

    Background:
        Given a certificate is issued with CN query-cert-1

    Rule: Certificate Listing

        Scenario: List certificates returns issued certificates with metadata
            When the MCP server invokes "list_certificates" with page 0 and pageSize 500
            Then the result MUST succeed
            And the items list MUST contain at least 1 certificate
            And each returned certificate MUST have a non-empty serial number
            And each returned certificate MUST have a non-empty subject
            And each returned certificate MUST have a non-empty issuer
            And each returned certificate MUST have a non-empty thumbprint
            And each returned certificate MUST have a valid NotBefore timestamp
            And each returned certificate MUST have a valid NotAfter timestamp
            And NotBefore must be before NotAfter

            When the MCP server invokes "list_certificates" with page 0 and pageSize 1
            And the result MUST succeed
            And the items list MUST contain at most 1 certificate
            And hasNextPage indicates whether there are more pages

        Scenario: List certificates rejects invalid pageSize
            When the MCP server invokes "list_certificates" with page 0 and pageSize 0
            Then the result MUST indicate failure
            And the error description contains "pageSize"

            When the MCP server invokes "list_certificates" with page 0 and pageSize 501
            Then the result MUST indicate failure
            And the error description contains "pageSize"

            When the MCP server invokes "list_certificates" with page 0 and pageSize -1
            Then the result MUST indicate failure
            And the error description contains "pageSize"

    Rule: Certificate Search

        Scenario: Search with serialNumber filter returns matching certificate
            When the MCP server invokes "search_certificates" with serialNumber matching the issued cert
            Then the result MUST succeed
            And the total count MUST be at least 1

        Scenario: Search with no filter parameters returns all certificates
            When the MCP server invokes "search_certificates" with no filter parameters
            Then the result MUST succeed
            And the items list MUST be a valid array

    Rule: Certificate Lookup by Serial

        Scenario: Get certificate by valid serial number succeeds
            When the MCP server invokes "get_certificate" with the issued certificate's serial number
            Then the result MUST succeed
            And the returned certificate MUST have a non-empty serial number
            And the returned certificate subject MUST be present
            And the returned certificate thumbprint MUST be present

        Scenario: Get certificate by non-existent serial returns CertificateNotFound
            When the MCP server invokes "get_certificate" with serial number "0000000000000000000000000000000000000000"
            Then the result MUST indicate failure
            And the error description contains "not found"

        Scenario: Get certificate with invalid hex serial returns error
            When the MCP server invokes "get_certificate" with serial number "GG"
            Then the result MUST indicate failure
            And the error description contains "hex"

        Scenario: Get certificate without serial number fails
            When the MCP server invokes "get_certificate" without providing a serial number
            Then the result MUST indicate failure
            And the error description contains "serialNumber"

    Rule: CA Certificate Retrieval

        Scenario: Get CA certificates returns root and intermediate chain
            When the MCP server invokes "get_ca_certificates" with includeFullChain false
            Then the result MUST succeed
            And the result MUST contain at least 1 certificate
            And each CA certificate MUST have a subject, issuer, serial number, and thumbprint

        Scenario: Get CA certificates with full chain includes rollover certificates
            When the MCP server invokes "get_ca_certificates" with includeFullChain true
            Then the result MUST succeed
            And the certificate count MUST be greater than or equal to 1

        Scenario: Get CA certificates by profile uses specified profile
            When the MCP server invokes "get_ca_certificates" with profileName "rsa"
            Then the result MUST succeed
            And the profiles list MUST include "rsa"
