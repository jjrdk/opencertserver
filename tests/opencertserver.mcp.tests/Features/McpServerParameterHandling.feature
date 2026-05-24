Feature: MCP Server Parameter Handling
    As an MCP client
    I want to pass parameters in various formats
    So that the server handles them correctly regardless of JSON serialization

    Background:
        Given the MCP server is initialized with a test CA

    Scenario: Integer parameters are parsed correctly from JsonElement
        When the MCP server invokes "list_certificates" with parameters:
             | Key      | Value     |
             | page     | 0         |
             | pageSize | 10        |
        Then the result MUST succeed

    Scenario: Boolean parameters are parsed correctly from JsonElement
        Given a certificate has been issued
        When the MCP server invokes "get_certificate" with parameters:
             | Key        | Value     |
             | serialNumber | {issued_serial} |
             | includePem | true      |
        Then the result MUST succeed

    Scenario: Array parameters are parsed correctly from JsonElement
        Given a certificate has been issued
        When the MCP server invokes "get_revocation_status" with parameters:
             | Key           | Value           |
             | serialNumbers | [{issued_serial}] |
        Then the result MUST succeed

    Scenario: Invalid hex serial number is rejected with clear error
        When the MCP server invokes "get_certificate" with parameters:
             | Key          | Value  |
             | serialNumber | ZZZZ   |
        Then the result MUST indicate failure
        And the error message MUST mention "hex"

    Scenario: Invalid hex in revocation status is rejected with clear error
        When the MCP server invokes "get_revocation_status" with parameters:
             | Key           | Value     |
              | serialNumbers | ["INVALID"] |
        Then the result MUST indicate failure
        And the error message MUST mention "hex"

    Scenario: Invalid hex in OCSP check is rejected with clear error
        When the MCP server invokes "check_ocsp_status" with parameters:
             | Key            | Value                                                            |
             | serialNumber   | ZZZZ                                                             |
             | issuerNameHash | 0000000000000000000000000000000000000000000000000000000000000000 |
             | issuerKeyHash  | 0000000000000000000000000000000000000000000000000000000000000000 |
        Then the result MUST indicate failure
        And the error message MUST mention "hex"

    Scenario: PEM-encoded CSR is accepted by sign_certificate
        When the MCP server invokes "sign_certificate" with a PEM CSR
        Then the result MUST succeed

    Scenario: DateTimeOffset parsing preserves timezone in sign_certificate
        When the MCP server invokes "sign_certificate" with ISO 8601 dates
        Then the result MUST succeed
