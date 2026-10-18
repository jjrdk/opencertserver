@iq @blackbox @linux-client
Feature: The OCSP responder (RFC 6960) answers a Linux relying party
  A relying party on Linux checks a certificate's status with `openssl ocsp` against a
  running OpenCertServer. These scenarios prove the responder is reachable, returns a
  signed response, and agrees with `openssl` about `good` / `revoked` status for a
  certificate the Linux client actually enrolled - the practical outcome a browser or
  TLS client would depend on.

  They complement the OCSP conformance suite; the new assertion is the *interoperable
  result an `openssl ocsp` client obtains over the network from the running install*.

  Rule: A good certificate returns good
  Scenario: A Linux relying party checks a live certificate
    Given a hardened OpenCertServer with a live certificate that the client enrolled
    When the Linux client runs "openssl ocsp" to query the responder for that certificate
    Then openssl reports the status as "good"
    And the response signature verifies against the responder key

  Rule: A revoked certificate returns revoked
  Scenario: A Linux relying party checks a revoked certificate
    Given a certificate that has been revoked with a reason
    When the Linux client runs "openssl ocsp" to query the responder for that certificate
    Then openssl reports the status as "revoked"

  Rule: Both the POST and the GET transports are reachable
  Scenario Outline: The responder answers the <transport> transport
    When the Linux client sends an OCSP request via <transport> using "openssl ocsp"
    Then the responder returns a signed "good" response for a live certificate

    Examples:
      | transport |
      | POST      |
      | GET       |
