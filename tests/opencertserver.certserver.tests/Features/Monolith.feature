Feature: In-process monolith
    The default deployment runs the CA, EST, ACME, RA, and public RA in one process. This
    regression guards the T1 invariant: the monolith still issues certificates (the in-process
    issuer is the default) and still rejects an anonymous /ca/csr request — ACME requires
    account-based JWS, so the CA endpoint is not an anonymous issuance surface.

    Scenario: The monolith issues an in-scope certificate
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA enrolls a certificate
        Then the RA receives a CA-issued certificate

    Scenario: The monolith rejects an anonymous certificate request
        Given a certificate server
        When an anonymous client submits a certificate request to the CA
        Then the CA rejects the anonymous request
