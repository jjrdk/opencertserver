@mcp-server-revocation
@mcp-get-crl
@mcp-check-ocsp-status
@mcp-get-revocation-status
Feature: MCP Revocation Check Tools

    This feature covers the revocation checking tools: get_crl, check_ocsp_status,
    and get_revocation_status. These tools allow clients to check the revocation status
    of certificates.

    Rule: CRL Retrieval

        Scenario: Get CRL returns current revocation list
            When the MCP server invokes "get_crl" with default parameters
            Then the result MUST succeed
            And the response MUST include a CRL profile name
            And the response MUST include a LastUpdate timestamp
            And the response MUST include a NextUpdate timestamp that is after LastUpdate
            And the CRL bytes MAY be present when includePem is false

        Scenario: Get CRL with profile name returns that profile's CRL
            When the MCP server invokes "get_crl" with profileName "rsa"
            Then the result MUST succeed
            And the response profile MUST be "rsa"

        Scenario: Get CRL with includePem returns DER-encoded CRL
            When the MCP server invokes "get_crl" with includePem true
            Then the result MUST succeed
            And the CRL bytes in the response MUST be base64-encoded

    Rule: OCSP Status Check (check_ocsp_status)

        Scenario: Check OCSP status for a good certificate returns Good
            Given a certificate is issued
            When the MCP server invokes "check_ocsp_status" with the certificate's serial number, issuer name hash, and issuer key hash
            Then the result MUST succeed
            And the status MUST be McpCertificateStatus.Good (1)
            And the response MUST include a ThisUpdate and NextUpdate timestamp
            And the NextUpdate MUST be after ThisUpdate

        Scenario: Check OCSP status for an unknown certificate returns Unknown
            When the MCP server invokes "check_ocsp_status" with serial number "00000000", issuer name hash "4141", and issuer key hash "4242"
            Then the result MUST succeed
            And the status MUST be McpCertificateStatus.Unknown (3)

        Scenario: Check OCSP status without required hashes returns error
            When the MCP server invokes "check_ocsp_status" with serial number "1234" but no issuer hashes
            Then the result MUST indicate failure
            And the error message MUST mention issuerNameHash or issuerKeyHash is required

        Scenario: Check OCSP status with invalid hex hashes returns error
            When the MCP server invokes "check_ocsp_status" with serial number "1234", issuer name hash "INVALID", and issuer key hash "NOPE"
            Then the result MUST indicate failure
            And the error message MUST mention hex encoding

    Rule: Bulk Revocation Status Check (get_revocation_status)

        Scenario: Check revocation status for a set of serial numbers returns per-certificate results
            Given a certificate is issued
            When the MCP server invokes "get_revocation_status" with an array containing the certificate's serial number
            Then the result MUST succeed
            And the response MUST have a TotalChecks equal to 1
            And the Checks array MUST contain one entry
            And the first check result MUST have serial number matching the requested one
            And the first check result MUST have status Good
            And the first check result MUST have FoundInStore equal to true

        Scenario: Check revocation status for a non-existent serial returns Unknown
            When the MCP server invokes "get_revocation_status" with serial number "0000000000000000000000000000000000000000"
            Then the result MUST succeed
            And the Checks array MUST contain one entry
            And the status MUST be McpCertificateStatus.Unknown (3)
            And FoundInStore MUST be false

        Scenario: Check revocation status with empty array returns error
            When the MCP server invokes "get_revocation_status" with an empty serialNumbers array
            Then the result MUST indicate failure
            And the error message MUST mention serialNumbers array is required

        Scenario: Check revocation status for mixed good and revoked certificates
            Given a certificate is issued
            And another certificate is issued and then revoked
            When the MCP server invokes "get_revocation_status" with both certificates' serial numbers
            Then the result MUST succeed
            And the Checks array MUST contain at least 2 entries
            And at least one result MUST have status Good
            And at least one result MUST have status Revoked (2)

        Scenario: Check revocation status with profile name uses that profile
            Given a certificate is issued
            When the MCP server invokes "get_revocation_status" with serial numbers and profileName "rsa"
            Then the result MUST succeed
            And the response profile MUST be "rsa"
