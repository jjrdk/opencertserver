Feature: Remote ACME issuer
    An ACME server can be separated from its certificate authority and issue through a backing
    certificate authority over a trusted HTTPS connection. The ACME process references a remote
    issuer (opencertserver.acme.remote) and never loads a CA key; the backing CA stays authoritative
    for scope and identity. A CA rejection (for example an out-of-scope identifier) is surfaced as an
    ACME error so the order fails cleanly.

    Scenario: An ACME order finalizes through a backing CA
        Given a certificate server
        And a remote ACME issuer pointed at the backing CA
        When an ACME order finalizes for "host.tenant-a.example.com"
        Then the backing CA returns a signed certificate chain

    Scenario: An out-of-scope identifier fails the order
        Given a certificate server
        And a remote ACME issuer pointed at the backing CA
        When an ACME order finalizes for the out-of-scope identifier "tenant-b.example.com"
        Then the order fails with a rejected identifier

    Scenario: A certificate is revoked over the wire
        Given a certificate server
        And a remote ACME issuer pointed at the backing CA using its client certificate
        When an ACME order finalizes for "host.tenant-a.example.com"
        And the certificate is revoked over the wire
        Then the revocation succeeds

    Scenario: A non-HTTPS backing CA is rejected at startup
        Given a non-HTTPS remote ACME configuration
        When the remote ACME host is configured
        Then startup is rejected
