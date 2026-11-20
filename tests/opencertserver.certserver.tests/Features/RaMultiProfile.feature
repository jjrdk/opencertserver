Feature: Registration authority supports multiple profiles
    An RA delegating to a backing certificate authority can serve every profile the CA supports,
    not a single one. The RA discovers the CA's profile set on demand (so it can pick up a profile
    set the CA has since updated) and can enroll a request against any one of those profiles by
    name. The RA's own profile configuration stays open: an empty delegated set means "all profiles
    the CA supports", a non-empty set restricts the RA to a subset.

    Scenario: An RA requests the set of profiles the CA supports
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA requests the supported profiles
        Then the supported profiles include "default" and "ecdsa"

    Scenario: An RA enrolls against a non-default profile
        Given a certificate server
        And an outbound RA peer for "host.tenant-a.example.com"
        When the RA enrolls a certificate against the "ecdsa" profile
        Then the RA receives a CA-issued certificate
