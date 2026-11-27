Feature: Public self-service registration authority
    Anonymous enrollment is exposed only through ACME domain validation on explicitly
    enabled profiles, with EAB and request-rate controls available as abuse safeguards.

    Scenario: Public enrollment succeeds after ACME domain validation
        Given a certificate server with Public RA enabled and rate limit 100000
        And an ACME client for RS256
        When the client requests a certificate
        Then the client receives a certificate

    Scenario: Anonymous direct CA signing is not a public enrollment path
        Given a certificate server with Public RA enabled and rate limit 60
        When an anonymous client submits a certificate request to the CA
        Then the CA rejects the anonymous request

    Scenario: Public ACME accounts require EAB when configured
        Given a certificate server with Public RA enabled, EAB required, and rate limit 60
        When an ACME client creates an account without EAB
        Then ACME account creation is rejected

    Scenario: ACME requests over the public limit receive 429
        Given a certificate server with Public RA enabled and rate limit 1
        When the client requests the ACME directory twice
        Then the first directory response is successful and the second is rate limited
