Feature: RA/CA protocol contract
    The registration authority (opencertserver.ra) and the certificate authority
    (opencertserver.ca.server) share one protocol package (opencertserver.ca.protocol).
    That package is the single source of truth for the paths, claims, headers and revocation
    proof so the two can be deployed independently without desynchronizing the wire contract.

    Scenario: The shared protocol constants define the wire contract
        When the RA and CA protocol constants are compared
        Then the shared paths, claims and headers are defined
        And the current protocol version is accepted and unsupported versions are rejected

    Scenario: An RA and a CA agree on the contract over HTTPS
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA enrolls a certificate
        Then the RA receives a CA-issued certificate
        And the peer request uses HTTPS

    Scenario: An out-of-scope RA request is rejected by the backing CA
        Given a certificate server
        And an outbound RA peer for "tenant-b.example.com"
        When the RA enrolls a certificate
        Then the central CA rejects the RA request
