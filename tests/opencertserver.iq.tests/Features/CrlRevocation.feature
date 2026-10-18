@iq @blackbox @linux-client @hardened
Feature: CRL publication and revocation (RFC 5280) are usable from Linux
  A Linux relying party (a browser, a TLS verifier, an `openssl crl`) must be able to
  fetch the CRL and see that a revoked certificate is in it. These scenarios prove the
  CRL is published, decodable, and consistent with a revocation that a Linux client
  performs against the running install.

  They complement the CRL/revocation conformance suite; the new assertion is the
  *end-to-end revocation a Linux client observes*: an authorized revocation shows up in
  the CRL an `openssl crl` client fetches over the wire.

  Rule: The CRL is published and decodable
  Scenario: A Linux client fetches the published CRL
    When the Linux client GETs "/ca/crl" with curl
    Then the response content-type is "application/pkix-crl"
    And the body decodes as a CRL with "openssl crl"

  Scenario: Per-profile CRL endpoints are reachable
    When the Linux client GETs a per-profile CRL with curl
    Then the response content-type is "application/pkix-crl"

  Rule: Revocation is enforced by proof of possession and role
  Scenario: A self-service revocation reaches the CRL
    Given a hardened OpenCertServer with an authorized client certificate
    When the Linux client revokes its own certificate via "DELETE /ca/revoke" (reason "keyCompromise")
    And the Linux client re-fetches the CRL with "openssl crl"
    Then the revoked serial is present in the CRL

  Scenario: An administrative revocation is authorized by the ca_admin role
    Given a hardened OpenCertServer and a caller authenticated with the "ca_admin" role
    When the Linux client submits a revocation for any certificate via "DELETE /ca/revoke"
    Then the revocation is accepted
    And the revoked serial appears in the fetched CRL

  Scenario: An unauthorized revocation is refused
    Given a hardened OpenCertServer and a caller with neither matching thumbprint nor the "ca_admin" role
    When the Linux client submits a revocation via "DELETE /ca/revoke"
    Then the response is HTTP 403

  Rule: Issued certificates carry a CRL Distribution Point
  Scenario: The CDP is embedded so a client knows where to look
    When the Linux client inspects a freshly issued certificate with "openssl x509 -text"
    Then the certificate carries a CRL Distribution Point
