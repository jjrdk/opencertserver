Feature: Device Attest End-to-End Flow
  As an ACME client with a TPM-backed key
  I want to complete the full device-attest-01 flow
  So that I receive a hardware-attested certificate

  Scenario: Full device-attest-01 flow validates challenge and marks it valid
    Given an initialized ACME server with device-attest-01 wired up
    And a device-attest-01 challenge exists with token "dGVzdE5vbmNlMTIz"
    When the device submits attestation evidence with matching nonce "dGVzdE5vbmNlMTIz" and a valid AIK certificate
    Then the challenge is marked as valid
    And no ACME error is recorded
