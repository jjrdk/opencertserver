Feature: SCEP over a backing certificate authority
    An SCEP server can be separated from its certificate authority and issue through a backing
    certificate authority over a trusted HTTPS connection. The SCEP process holds no CA key: it
    forwards every enrollment and renewal to the CA and stores only its SCEP RA certificate and the
    replay protection. The CA stays authoritative for scope and identity.

    Scenario: A device enrolls through a backing CA
        Given a SCEP server backed by a separate certificate authority
        When a client enrolls with the challenge password "geheim"
        Then the certificate is issued by the backing CA

    Scenario: GetCACert returns the chain the backing CA publishes
        Given a SCEP server backed by a separate certificate authority
        When a client asks for the CA certificate
        Then the CA certificate is the one the backing CA publishes

    Scenario: A renewal supersedes the previous certificate at the backing CA
        Given a client holding a certificate renewed through a backing CA
        When the client renews it through the SCEP host with a new key
        Then the renewal keeps the subject and rotates the key
        And the superseded certificate is revoked at the backing CA

    Scenario: A non-HTTPS backing CA is rejected at startup
        Given a non-HTTPS SCEP backing CA configuration
        When the SCEP host is configured
        Then startup is rejected
