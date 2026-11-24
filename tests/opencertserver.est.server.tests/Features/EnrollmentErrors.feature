Feature: EST enrollment errors do not disclose internal details

    Scenario Outline: Malformed enrollment requests receive a safe client error
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a "<kind>" CSR to "<endpoint>"
        Then the EST response is 400 with "The CSR could not be read."

        Examples:
          | endpoint       | kind              |
          | simpleenroll   | invalid base64    |
          | simplereenroll | invalid base64    |
          | serverkeygen   | invalid base64    |
          | simpleenroll   | invalid DER       |
          | simplereenroll | invalid DER       |
          | serverkeygen   | invalid DER       |
          | simpleenroll   | unsupported key   |
          | simplereenroll | unsupported key   |
          | serverkeygen   | unsupported key   |
          | simpleenroll   | invalid signature |
          | simplereenroll | invalid signature |
          | simpleenroll   | malformed keyusage |
          | simplereenroll | malformed keyusage |
          | serverkeygen   | malformed keyusage |
          | simpleenroll   | malformed SAN     |
          | simplereenroll | malformed SAN     |
          | serverkeygen   | malformed SAN     |
          | simpleenroll   | malformed otherName |

    Scenario: Server key generation deliberately ignores the CSR signature
        Given a certificate server that complies with EST (RFC 7030)
        When a client submits a "invalid signature" CSR to "serverkeygen"
        Then the EST response status is 200

    Scenario Outline: Internal validator failures are logged but not disclosed
        Given an EST validator that fails with "<failure>" during signing
        And a certificate server that complies with EST (RFC 7030)
        When a client submits a "valid" CSR to "<endpoint>"
        Then the EST response is 500 with "Internal error while issuing the certificate."
        And the internal failure is logged

        Examples:
          | endpoint       | failure       |
          | simpleenroll   | configuration |
          | simplereenroll | configuration |
          | serverkeygen   | configuration |
          | simpleenroll   | cryptographic |
          | simplereenroll | cryptographic |
          | serverkeygen   | cryptographic |
