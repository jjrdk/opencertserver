@mcp-server-certificate-operations
@mcp-sign-certificate
@mcp-revoke-certificate
Feature: MCP Certificate Operations

    This feature covers the certificate operation tools: sign_certificate and revoke_certificate.
    These tools allow clients to issue new certificates and revoke existing ones.

    Rule: Certificate Signing

        Scenario: Signing a valid CSR issues a certificate
            Given a valid CSR is available
            When the MCP server invokes "sign_certificate" with that CSR
            Then the result MUST succeed
            And the returned certificate serial number MUST be non-empty
            And the returned certificate subject MUST match the CSR subject
            And the returned certificate issuer MUST match the CA's subject
            And the returned certificate must have a valid NotBefore and NotAfter
            And the returned certificate must have a PublicKeyAlgorithm and PublicKeySize greater than zero

        Scenario: Signing a valid CSR with PEM output returns PEM and chain
            Given a valid CSR is available
            When the MCP server invokes "sign_certificate" with that CSR and includePem true
            Then the result MUST succeed
            And the returned certificate MUST have a Pem field containing "-----BEGIN CERTIFICATE-----"
            And the returned certificate MUST have a PemChain field containing "-----BEGIN CERTIFICATE-----"
            And the PemChain MUST contain at least 2 certificates (intermediate + root)

        Scenario: Signing a CSR with explicit validity dates uses those dates
            Given a valid CSR is available
            When the MCP server invokes "sign_certificate" with that CSR, notBefore "2025-01-01T00:00:00Z", and notAfter "2026-01-01T00:00:00Z"
            Then the result MUST succeed
            And the returned certificate NotBefore MUST be on or before "2025-01-01T00:00:00Z"
            And the returned certificate NotAfter MUST match "2026-01-01T00:00:00Z"

        Scenario: Signing an invalid CSR fails with certificate signing error
            Given an invalid CSR is available
            When the MCP server invokes "sign_certificate" with an invalid CSR body
            Then the result MUST indicate failure
            And the error code MUST be McpErrorCode.CertificateSigningFailed
            And the error message MUST mention that the CSR could not be parsed

        Scenario: Signing without a CSR fails
            When the MCP server invokes "sign_certificate" without providing a CSR string
            Then the result MUST indicate failure
            And the error message MUST mention that csr is required

        Scenario: Signing a valid CSR stores the certificate in the inventory
            Given a valid CSR is available
            When the MCP server invokes "sign_certificate" with that CSR
            Then the result MUST succeed
            And the issued certificate MUST appear in the certificate inventory
            When the MCP server invokes "list_certificates" with page 0 and pageSize 500
            Then the total count MUST be at least 1

    Rule: Certificate Revocation

        Scenario: Revoke a valid certificate by serial number
            Given a certificate is issued
            When the MCP server invokes "revoke_certificate" with that certificate's serial number and reason "KeyCompromise"
            Then the result MUST succeed
            And the certificate MUST be marked as revoked in the inventory
            When the MCP server invokes "list_certificates" with page 0 and pageSize 500
            Then at least one certificate item MUST have IsRevoked true

        Scenario: Revoke a certificate with all optional fields
            Given a certificate is issued
            When the MCP server invokes "revoke_certificate" with that certificate's serial number, reason "CACompromise", reason 2, and description "Test revocation"
            Then the result MUST succeed
            And the revocation reason stored MUST reflect "CACompromise"

        Scenario: Revoke a non-existent certificate
            When the MCP server invokes "revoke_certificate" with serial number "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            Then the result MUST indicate failure
            And the error message MUST mention that no certificate with that serial was found

        Scenario: Revoke without serial number fails
            When the MCP server invokes "revoke_certificate" without a serial number
            Then the result MUST indicate failure
            And the error message MUST mention that serialNumber is required
