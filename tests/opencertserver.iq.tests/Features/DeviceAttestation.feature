@iq @blackbox @linux-client @hardened
Feature: The device-attest-01 challenge is advertised and fails closed
  `device-attest-01` lets a hardware device obtain a certificate by proving its identity
  via an Attestation Identity Key (AIK) and a TPM proof, instead of a domain. On a
  hardened install the type is always advertised in the directory but the challenge is
  *gated*: with no configured trust roots, no device-attest-01 challenge is offered and
  any that arrives is rejected (fail-closed). These scenarios verify the deployment
  posture a Linux client can observe.

  They complement the device-attest conformance suite; the new assertion is the
  *client-observable* posture against the running install.

  Rule: The challenge type is advertised
  Scenario: The directory advertises device-attest-01
    When the Linux client GETs "/directory" with curl
    And the Linux client filters the meta block with "jq"
    Then "meta.challengeTypesWithAdditionalContent" contains "device-attest-01"

  Rule: The challenge is gated when no trust roots are configured
  Scenario: With no configured trust roots a device-attest-01 challenge is not offered
    Given a hardened OpenCertServer runs with the default empty IAttestationTrustProvider
    When the Linux client submits an order requiring device-attest-01
    Then the returned authorizations offer only "http-01" and "dns-01"

  Scenario: A device-attest-01 answer with no proof is rejected
    Given a hardened OpenCertServer runs with a non-empty set of trust roots
    When the Linux client answers a device-attest-01 challenge with a malformed or empty proof
    Then the challenge is rejected with "invalid_attestation"

  Scenario: A reused nonce is rejected
    Given a hardened OpenCertServer runs with a non-empty set of trust roots
    When the Linux client submits a device-attest-01 answer twice with the same proof nonce
    Then the first answer validates and the second is rejected as "replay_nonce"
