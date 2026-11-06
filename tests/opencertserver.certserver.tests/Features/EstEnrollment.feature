Feature: Est enrollment
Enrollment over secure transport using JWT

    Scenario Outline: Enroll with JWT
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I enroll with a valid JWT
        Then I should get a certificate

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |

    Scenario Outline: Re-Enroll with JWT
        Given the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I enroll with a valid JWT
        And I get a certificate
        And I use the certificate to re-enroll without a valid JWT
        Then I should get a new certificate

        Examples:
          | Storage    |
          | in-memory  |
          | postgresql |
          | mssql      |
