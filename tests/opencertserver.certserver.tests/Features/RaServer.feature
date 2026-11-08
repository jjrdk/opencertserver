Feature: Registration authority host
    The RA host (opencertserver.ra.server) is a thin delegator. It forwards certificate
    operations to a backing certificate authority over a trusted HTTPS connection using the RA
    peer client (opencertserver.ra), which itself talks to the CA through opencertserver.ca.client.
    The RA never grants scope the CA has not delegated: out-of-scope requests are rejected by the
    backing CA and the RA surfaces the 400 to its caller.

    Scenario: The RA host enrolls an in-scope subject via the backing CA
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA enrolls a certificate
        Then the RA receives a CA-issued certificate
        And the peer request uses HTTPS

    Scenario: An out-of-scope subject is rejected by the backing CA
        Given a certificate server
        And an outbound RA peer for "tenant-b.example.com"
        When the RA enrolls a certificate
        Then the central CA rejects the RA request

    Scenario: A renewal re-applies the CA policy
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA enrolls a certificate
        And the RA renews the certificate
        Then the RA receives a CA-issued certificate
        And the peer request uses HTTPS

    Scenario: The RA host enforces HTTPS-only transport to the CA
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA enrolls a certificate
        Then the peer request uses HTTPS

    # F1: the RA EST enrollment surface must be protected by a signature-verified JWT. A RA that
    # cannot verify the JWT signature must refuse to start rather than accept any well-formed token.
    Scenario: The RA refuses to start with a signature-unverified JWT
        Given a RA host with no JWT signing key
        When the RA host configures EST authentication
        Then the RA host fails to start

    Scenario: A JWT signed with a key other than the RA's is rejected
        Given a RA host with a JWT signing key
        When the RA validates a JWT signed with a key that is not its own
        Then the JWT is rejected because its signature does not verify

    Scenario: A JWT signed with the RA's own signing key is accepted
        Given a RA host with a JWT signing key
        When the RA validates a JWT signed with its own signing key
        Then the JWT is accepted
