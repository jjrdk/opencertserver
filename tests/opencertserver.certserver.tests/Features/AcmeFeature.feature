Feature: ACME certificate flow

    Scenario Outline: Can complete certificate flow
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an ACME client for <keyAlgorithm>
        When the client requests a certificate
        Then the client receives a certificate

    Examples:
      | keyAlgorithm | Storage    |
      | RS256        | in-memory  |
      | RS256        | postgresql |
      | RS256        | mssql      |
      | ES256        | in-memory  |
      | ES256        | postgresql |
      | ES256        | mssql      |
      | ES384        | in-memory  |
      | ES384        | postgresql |
      | ES384        | mssql      |
      | ES512        | in-memory  |
      | ES512        | postgresql |
      | ES512        | mssql      |
