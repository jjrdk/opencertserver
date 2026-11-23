Feature: ACME client errors do not disclose parser diagnostics

    Scenario Outline: An unreadable CSR gets a fixed badCSR detail
        When the ACME CSR validator receives "<csr>"
        Then the CSR validation error has the fixed detail "The CSR could not be parsed."

        Examples:
          | csr                   |
          | not-valid-base64!     |
          | AQIDBA==              |

    Scenario: A JSON parser failure gets a fixed malformed problem detail
        When an ACME endpoint encounters a JSON parser failure
        Then the ACME problem has the fixed detail "The request JSON could not be read."

    Scenario: The default HTTP challenge validator can be resolved
        When the ACME server uses its default HTTP client registration
        Then the HTTP challenge validator can be resolved
