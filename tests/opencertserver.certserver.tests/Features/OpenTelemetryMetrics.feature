Feature: OpenTelemetry Metrics

    Rule: EST metrics are emitted

        Scenario Outline: EST /cacerts endpoint increments request counter
            Given the certificate server storage is "<Storage>"
            And a certificate server
            And an EST client
            And an OpenTelemetry meter listener
            When I fetch the CA certs over EST
            Then the EST cacerts request counter should be greater than zero

            Examples:
              | Storage    |
              | in-memory  |
              | postgresql |
              | mssql      |

        Scenario Outline: EST /simpleenroll endpoint increments request counter
            Given the certificate server storage is "<Storage>"
            And a certificate server
            And an EST client
            And an OpenTelemetry meter listener
            When I enroll with a valid JWT
            Then the EST simpleenroll request counter should be greater than zero

            Examples:
              | Storage    |
              | in-memory  |
              | postgresql |
              | mssql      |

    Rule: OCSP metrics are emitted

        Scenario Outline: OCSP request increments counter
            Given the certificate server storage is "<Storage>"
            And a certificate server
            And an EST client
            And an OpenTelemetry meter listener
            When I enroll with a valid JWT
            And I get a certificate
            And I check the OCSP status of my certificate
            Then the OCSP request counter should be greater than zero

            Examples:
              | Storage    |
              | in-memory  |
              | postgresql |
              | mssql      |

    Rule: CRL metrics are emitted

        Scenario Outline: CRL request increments counter
            Given the certificate server storage is "<Storage>"
            And a certificate server
            And an EST client
            And an OpenTelemetry meter listener
            When I request the CRL
            Then the CRL request counter should be greater than zero

            Examples:
              | Storage    |
              | in-memory  |
              | postgresql |
              | mssql      |

