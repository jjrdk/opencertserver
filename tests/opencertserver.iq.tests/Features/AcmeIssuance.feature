@iq @blackbox @linux-client
Feature: RFC 8555 ACME issuance works for a Linux web-application client
  A web application that needs a TLS certificate obtains one automatically with a
  standard ACME client - here `acme.sh` and `certbot`, the two canonical Linux ACME
  clients, driven from the client container. These scenarios prove the full order lifecycle is usable from
  Linux end-to-end (a real issuance that yields a verifiable chain), not just that the
  endpoints exist in process.

  They complement RFC 8555 conformance; the new assertion is that the canonical ACME
  clients, run from Linux, complete issuance, renewal, revocation, EAB binding and
  TOS-reagreement against the running install. Running two independent ACME client
  implementations guards against the server only interoperating with one of them.

  Rule: The ACME directory is reachable and complete
  Scenario: The Linux client reads the ACME directory
    When the Linux client GETs "/directory" with curl
    Then the response is HTTP 200
    And the directory JSON, filtered with "jq", lists "newNonce", "newAccount", "newOrder", "keyChange" and "revokeCert"

  Rule: A domain is validated and a certificate is issued (http-01)
  Scenario: acme.sh issues a certificate via the http-01 challenge
    Given a hardened OpenCertServer is reachable
    And an ACME account exists on the server
    When the Linux client runs "acme.sh" to issue "acme.example.com" via the "http-01" challenge
    Then acme.sh exits 0
    And the issued certificate chains to the published CA with "openssl verify"

  Rule: A domain is validated and a certificate is issued (dns-01)
  Scenario: acme.sh issues a certificate via the dns-01 challenge
    Given a hardened OpenCertServer is reachable
    And an ACME account exists on the server
    When the Linux client runs "acme.sh" to issue "dns.example.com" via the "dns-01" challenge
    Then acme.sh exits 0
    And the issued certificate chains to the published CA

  Rule: New accounts can be bound by EAB
  Scenario: new-account succeeds with external account binding
    Given EAB credentials "kid" and "hmac" are supplied to the Linux client
    When the Linux client creates an ACME account with EAB via "acme.sh"
    Then the account is created (HTTP 200/201) with a location

  Rule: A changed term of service forces re-agreement
  Scenario: new-order after a TOS bump requires re-agreement
    Given an ACME account exists whose agreed TOS predates the server's "AcmeServer:TOS:LastUpdate"
    When the Linux client submits an order for a validated domain
    Then the response is HTTP 403 "userActionRequired"
    Then the response carries a "Link" header to the terms-of-service
    When the Linux client agrees to the TOS via an account update
    And the Linux client submits the order again
    Then the order is accepted

  Rule: Certificates can be revoked
  Scenario: revoking the certificate a Linux client obtained
    Given a Linux client holds a valid certificate issued by the server
    When the Linux client revokes it via "acme.sh --revoke"
    And the Linux client re-reads the server's CRL
    Then the revoked serial appears in the CRL fetched with "openssl crl"

  Rule: Errors are problem+json
  Scenario: A malformed ACME request returns RFC 7807 problem+json
    When the Linux client POSTs a request missing a "nonce" to an ACME endpoint
    Then the response content-type is "application/problem+json"
    And the body contains an "type" and a "status"

  Rule: certbot, the EFF ACME client, completes the same lifecycle
  Scenario: certbot registers an ACME account
    Given a hardened OpenCertServer is reachable
    When the Linux client registers an ACME account via "certbot register"
    Then certbot exits 0
    And certbot stores the account location returned by the server

  Scenario Outline: certbot issues a certificate via the <challenge> challenge
    Given a hardened OpenCertServer is reachable
    And a "certbot" ACME account exists on the server
    When the Linux client runs "certbot" to issue "<domain>" via the "<challenge>" challenge
    Then certbot exits 0
    And the issued certificate chains to the published CA with "openssl verify"

    Examples:
      | challenge | domain                  |
      | http-01   | certbot.example.com     |
      | dns-01    | certbot-dns.example.com |

  Scenario: certbot new-account succeeds with external account binding
    Given EAB credentials "kid" and "hmac" are supplied to the Linux client
    When the Linux client creates an ACME account with EAB via "certbot"
    Then the account is created (HTTP 200/201) with a location

  Scenario: certbot renews the certificate it obtained
    Given a Linux client holds a valid certificate for "certbot-renew.example.com" issued via "certbot"
    When the Linux client renews it via "certbot renew --force-renewal"
    Then certbot exits 0
    And the renewed certificate has a new serial and chains to the published CA

  Scenario: certbot revokes the certificate it obtained
    Given a Linux client holds a valid certificate for "certbot-revoke.example.com" issued via "certbot"
    When the Linux client revokes it via "certbot revoke"
    And the Linux client re-reads the server's CRL
    Then the revoked serial appears in the CRL fetched with "openssl crl"
