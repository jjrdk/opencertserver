Feature: OCSP lookup

    Scenario Outline: Certificate revocation
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I enroll with a valid JWT
        And I get a certificate
        Then the certificate should be valid in OCSP
        When I revoke the certificate
        Then the certificate should be revoked in OCSP

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: Unknown certificate
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I check OCSP for an unknown certificate
        Then the response should indicate the certificate is unknown

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |
