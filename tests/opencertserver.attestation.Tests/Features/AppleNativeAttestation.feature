Feature: Apple Native Attestation (macOS)
  As a developer on macOS
  I want the Apple attestation provider to call Apple's Security.framework natively
  So that real hardware cryptographic operations are verified, not just mocks

  @native @apple
  Scenario: Generate SE-backed key and verify attestation signature on macOS
    Given the SecurityFramework Apple interop is available on this platform
    When the provider generates a hardware-backed key via Apple Security.framework
    Then a non-empty keyId is returned from the native call
    When the key is attested with a SHA-256 hash of a server challenge
    Then the attestation object contains a DER ECDSA signature and an EC public key
    And the ECDSA signature in the attestation object verifies correctly against the challenge hash

  @native @apple
  Scenario: Attestation object from different challenge produces a different signature
    Given the SecurityFramework Apple interop is available on this platform
    When the provider generates a hardware-backed key via Apple Security.framework
    And the key is attested with challenge "challenge-one"
    And the key is attested with challenge "challenge-two"
    Then the two attestation signatures are different

  @native @apple
  Scenario: Calling GenerateKeyAsync on a non-Apple platform throws PlatformNotSupportedException
    Given this test is NOT running on macOS
    When GenerateKeyAsync is called on SecurityFrameworkAppleAttestInterop
    Then a PlatformNotSupportedException is thrown from the native interop
