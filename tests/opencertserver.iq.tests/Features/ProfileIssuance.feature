@iq @blackbox @linux-client @hardened
Feature: Profile-controlled certificate content is what the client receives
  A profile fixes the `certificatePolicies`, `keyUsage`, and `extendedKeyUsage` of every
  certificate it issues, regardless of what the CSR asks for. On a hardened install the
  client must *receive* the profile's assertions, not the CSR's. These scenarios verify
  the observable outcome a Linux client sees by inspecting the issued certificate with
  `openssl x509 -text`, and that both key algorithms issue.

  They complement the profile conformance suite; the new assertion is that a Linux
  client, over the network, *receives* the profile-pinned extensions.

  Rule: Profile-fixed extensions appear on the issued certificate
  Scenario: The profile's certificatePolicies are present
    Given a profile that fixes certificatePolicies to include policy "1.3.6.1.4.1.999"
    When the Linux client enrolls a certificate from that profile with "est-client"
    And inspects the issued certificate with "openssl x509 -text"
    Then the certificatePolicies extension contains "1.3.6.1.4.1.999"

  Scenario: The profile's critical keyUsage replaces the CSR's
    Given a profile that fixes keyUsage to "keyEncipherment,dataEncipherment"
    When the Linux client enrolls from that profile asking for "digitalSignature" in the CSR
    And inspects the issued certificate with "openssl x509 -text"
    Then the critical keyUsage is "keyEncipherment,dataEncipherment"

  Scenario: The profile's extendedKeyUsage replaces the CSR's
    Given a profile that fixes extendedKeyUsage to "serverAuth"
    When the Linux client enrolls from that profile asking for "clientAuth" in the CSR
    And inspects the issued certificate with "openssl x509 -text"
    Then the extendedKeyUsage is "serverAuth"

  Rule: Non-CA profiles reject requests for CA issuance
  Scenario: A basicConstraints:CA:TRUE request is rejected on a non-CA profile
    Given a profile that does not authorise CA issuance
    When the Linux client enrolls from that profile with "basicConstraints: CA:TRUE" in the CSR
    Then enrollment is rejected with HTTP 400 because CA issuance is not authorised
    And the Linux client receives no issued certificate

  Rule: Both key algorithms issue
  Scenario Outline: The <key> profile issues a certificate the Linux client verifies
    Given a hardened OpenCertServer with a <key> profile
    When the Linux client enrolls from the <key> profile and inspects the result with "openssl x509 -text"
    Then the certificate's public key is a <key> key
    And the certificate chains to the published CA

    Examples:
      | key |
      | RSA |
      | EC  |
