Feature: OpenTelemetry Metrics

    Background:
        Given a certificate server
        And an EST client
        And an OpenTelemetry meter listener

    Rule: EST metrics are emitted

        Scenario: EST /cacerts endpoint increments request counter
            When I fetch the CA certs over EST
            Then the EST cacerts request counter should be greater than zero

        Scenario: EST /simpleenroll endpoint increments request counter
            When I enroll with a valid JWT
            Then the EST simpleenroll request counter should be greater than zero

    Rule: OCSP metrics are emitted

        Scenario: OCSP request increments counter
            When I enroll with a valid JWT
            And I get a certificate
            And I check the OCSP status of my certificate
            Then the OCSP request counter should be greater than zero

    Rule: CRL metrics are emitted

        Scenario: CRL request increments counter
            When I request the CRL
            Then the CRL request counter should be greater than zero

