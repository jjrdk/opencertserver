Feature: Device Attest Challenge Validation
  As an ACME server
  I want to validate device-attest-01 challenges
  So that only properly attested devices receive certificates

  # ─── Chain verification (S-II) ───────────────────────────────────────────────

  Scenario: Self-signed AIK certificate without injected trusted root is rejected
    Given a device-attest-01 challenge with token "dmFsaWROb25jZQ"
    And the challenge has extra data with matching nonce "dmFsaWROb25jZQ" and a self-signed AIK certificate
    When the server validates the challenge
    Then the result is not valid
    And the error type contains "invalid_attestation"

  Scenario: AIK certificate signed by an injected trusted CA passes chain verification
    Given a device-attest-01 challenge with token "dmFsaWROb25jZQ"
    And the challenge has extra data with matching nonce "dmFsaWROb25jZQ", a trusted CA-signed AIK certificate, and a valid TPM proof signed by the AIK key
    When the server validates the challenge with a trusted CA injected
    Then the result is valid
    And there is no error

  # ─── Proof field verification (S-I) ─────────────────────────────────────────

  Scenario: Proof containing garbage bytes fails validation
    Given a device-attest-01 challenge with token "dmFsaWROb25jZQ"
    And the challenge has extra data with matching nonce "dmFsaWROb25jZQ", a trusted CA-signed AIK certificate, and garbage proof bytes
    When the server validates the challenge with a trusted CA injected
    Then the result is not valid
    And the error type contains "invalid_attestation"

  Scenario: Proof with wrong TPM magic value fails validation
    Given a device-attest-01 challenge with token "dmFsaWROb25jZQ"
    And the challenge has extra data with matching nonce "dmFsaWROb25jZQ", a trusted CA-signed AIK certificate, and a proof with invalid TPM magic
    When the server validates the challenge with a trusted CA injected
    Then the result is not valid
    And the error type contains "invalid_attestation"

  Scenario: Proof with wrong attestation type fails validation
    Given a device-attest-01 challenge with token "dmFsaWROb25jZQ"
    And the challenge has extra data with matching nonce "dmFsaWROb25jZQ", a trusted CA-signed AIK certificate, and a proof with wrong attestation type
    When the server validates the challenge with a trusted CA injected
    Then the result is not valid
    And the error type contains "invalid_attestation"

  Scenario: Proof whose extra data does not match the challenge token fails validation
    Given a device-attest-01 challenge with token "dmFsaWROb25jZQ"
    And the challenge has extra data with matching nonce "dmFsaWROb25jZQ", a trusted CA-signed AIK certificate, and a proof with mismatched extra data
    When the server validates the challenge with a trusted CA injected
    Then the result is not valid
    And the error type contains "invalid_attestation"

  Scenario: Empty proof field with valid AIK chain fails validation
    Given a device-attest-01 challenge with token "dmFsaWROb25jZQ"
    And the challenge has extra data with matching nonce "dmFsaWROb25jZQ", a trusted CA-signed AIK certificate, and an empty proof
    When the server validates the challenge with a trusted CA injected
    Then the result is not valid
    And the error type contains "invalid_attestation"

  # ─── Anti-replay (S-III) ─────────────────────────────────────────────────────

  Scenario: Previously consumed nonce is rejected as replay
    Given a device-attest-01 challenge with token "cmVwbGF5Tm9uY2U"
    And the challenge has extra data with matching nonce "cmVwbGF5Tm9uY2U", a trusted CA-signed AIK certificate, and a valid TPM proof signed by the AIK key
    When the server validates the challenge with a trusted CA injected
    And the server validates the same challenge again with a trusted CA injected
    Then the second result is not valid
    And the second error type contains "replay_nonce"

  # ─── Existing nonce / missing data scenarios ─────────────────────────────────

  Scenario: Nonce mismatch causes validation failure
    Given a device-attest-01 challenge with token "bm9uY2VB"
    And the challenge has extra data with a different nonce "bm9uY2VC"
    When the server validates the challenge
    Then the result is not valid
    And the error type contains "invalid_nonce"

  Scenario: Missing attestation proof is rejected
    Given a device-attest-01 challenge with token "dmFsaWROb25jZQ"
    And the challenge has no extra data
    When the server validates the challenge
    Then the result is not valid
    And the error type contains "device_attestation"

  Scenario: Invalid AIK chain causes validation failure
    Given a device-attest-01 challenge with token "dmFsaWROb25jZQ"
    And the challenge has extra data with matching nonce "dmFsaWROb25jZQ" but no AIK certificate
    When the server validates the challenge
    Then the result is not valid
    And the error type contains "invalid_attestation"
