Feature: Backing CA HTTP client
    A registration authority or an ACME server can act as its own process and issue and revoke
    certificates through a backing certificate authority over a trusted HTTPS connection.
    The client (opencertserver.ca.client) is the outbound half of that trusted connection: it never
    makes a local scope or identity decision, so the backing CA stays authoritative.

    Scenario: A backing CA issues a signed chain over the HTTP client
        Given a certificate server
        And a backing CA client for "host.tenant-a.example.com"
        When the client signs a certificate request
        Then the client receives a CA-issued certificate
        And the client uses HTTPS

    Scenario: An out-of-scope request surfaces as a signing error
        Given a certificate server
        And a backing CA client for "tenant-b.example.com"
        When the client signs a certificate request
        Then the backing CA reports a signing error

    Scenario: A non-HTTPS backing CA is rejected at configuration
        Given a non-HTTPS backing CA configuration
        When the backing CA client is built from configuration
        Then the configuration is rejected

    Scenario: An mTLS client revokes an in-scope certificate
        Given a certificate server
        And a backing CA client for "host.tenant-a.example.com" using its client certificate
        When the client signs a certificate request
        And the client revokes the certificate
        Then the client revocation succeeds
