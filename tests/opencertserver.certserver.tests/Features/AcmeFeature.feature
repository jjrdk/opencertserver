Feature: ACME certificate flow

    Scenario: Can complete certificate flow
        Given a certificate server
        And an ACME client for <keyAlgorithm>
        When the client requests a certificate
        Then the client receives a certificate

    Examples:
      | keyAlgorithm |
      | RS256        |
      | ES256        |
      | ES384        |
      | ES512        |
