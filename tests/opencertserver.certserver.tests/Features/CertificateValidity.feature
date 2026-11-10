@nonparallelizable
Feature: Certificate validity does not depend on the server time zone
When no notBefore is requested, certificates are valid from midnight UTC of the
day they are issued - whatever the local time zone of the server (issue #81).
EST never passes a notBefore, so every EST enrollment takes this default; the
CA's own certificate is created the same way.

    Scenario Outline: Validity starts at midnight UTC in any server time zone
        Given the server time zone is <zone>
        And the certificate server storage is "<Storage>"
        And a certificate server
        And an EST client
        When I enroll with a valid JWT
        Then the certificate should be valid from midnight UTC today
        And the CA certificate should be valid from midnight UTC today

        Examples:
          | zone                | Storage    |
          | UTC                 | in-memory  |
          | UTC                 | postgresql |
          | UTC                 | mssql      |
          | America/Los_Angeles | in-memory  |
          | America/Los_Angeles | postgresql |
          | America/Los_Angeles | mssql      |
          | Asia/Tokyo          | in-memory  |
          | Asia/Tokyo          | postgresql |
          | Asia/Tokyo          | mssql      |
