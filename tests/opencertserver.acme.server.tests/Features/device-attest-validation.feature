Feature: Device Attest Challenge Validation
  As an ACME server
  I want to validate device-attest-01 challenges
  So that only properly attested devices receive certificates

  Scenario: Valid device attestation proof is accepted
    Given a device-attest-01 challenge with token "dmFsaWROb25jZQ"
    And the challenge has extra data with matching nonce "dmFsaWROb25jZQ" and a valid AIK certificate
    When the server validates the challenge
    Then the result is valid
    And there is no error

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
