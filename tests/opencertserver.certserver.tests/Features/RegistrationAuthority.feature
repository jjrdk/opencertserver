Feature: Outbound registration-authority peer
    An RA delegates certificate operations to a central CA over HTTPS and may act only
    within the DNS scopes and profiles recorded by that CA.

    Scenario: An RA enrolls for an in-scope subject over outbound HTTPS
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA enrolls a certificate
        Then the RA receives a CA-issued certificate
        And the peer request uses HTTPS

    Scenario: An RA cannot enroll for an out-of-scope subject
        Given a certificate server
        And an outbound RA peer for "tenant-b.example.com"
        When the RA enrolls a certificate
        Then the central CA rejects the RA request

    Scenario: An RA renews an in-scope certificate over outbound HTTPS
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA enrolls a certificate
        And the RA renews the certificate
        Then the RA receives a CA-issued certificate
        And the peer request uses HTTPS

    Scenario: An mTLS RA revokes an in-scope certificate
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com" using its client certificate
        When the RA enrolls a certificate
        And the RA revokes the certificate
        Then the RA revocation succeeds

    Scenario: A certificate with an RA common name needs an explicitly provisioned fingerprint
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com" using an unprovisioned client certificate
        When the RA enrolls a certificate
        Then the central CA rejects the RA request

    Scenario: The customer RA needs no inbound listener
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA enrolls a certificate
        Then the RA receives a CA-issued certificate
        And the peer request uses HTTPS

    # F3: an RA is bound to a delegated DNS scope on both the subjectAltName and the subject CN, so
    # it cannot carry a common name outside its scope.
    Scenario: An RA cannot enroll with a subject common name outside its scope
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA enrolls a certificate with a common name outside its scope
        Then the central CA rejects the RA request
