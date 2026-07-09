Feature: Apple Attestation Object Validation (macOS native)
As a security engineer verifying Apple device attestation
I want to validate attestation objects against Apple's validation spec
So that only genuine device attestations are accepted

@native
@apple
Scenario: Generate valid key and attestation object with correct crypto structure
    Given the SecurityFramework Apple interop is available on this platform
    When the provider generates a hardware-backed key via Apple Security.framework
    Then a non-empty keyId is returned from the native call
    And the keyId format matches Apple AppAttest conventions

@native
@apple
Scenario: Attestation signature verifies against known challenge and public key
    Given the SecurityFramework Apple interop is available on this platform
    When the provider generates a hardware-backed key via Apple Security.framework
    And the key is attested with a known challenge hash
    Then the signature in the attestation object correctly verifies against the challenge using the embedded public key

@native
@apple
Scenario: Attestation object structure matches expected Apple format
    Given the SecurityFramework Apple interop is available on this platform
    When the provider generates a hardware-backed key via Apple Security.framework
    And the key is attested with a known challenge hash
    Then the attestation object has a valid length-prefixed DER signature at offset 0
    And the attestation object contains a 65-byte X9.62 uncompressed P-256 public key

@native
@apple
Scenario: Signature is deterministically different for different challenges
    Given the SecurityFramework Apple interop is available on this platform
    When the provider generates a hardware-backed key via Apple Security.framework
    And the key is attested with two different challenge hashes
    Then the two attestation signatures are cryptographically distinct

@native
@apple
Scenario: keyId equals SHA-256 hash of the public key bytes
    Given the SecurityFramework Apple interop is available on this platform
    When the provider generates a hardware-backed key via Apple Security.framework
    And the key is attested with a known challenge hash
    Then the keyId matches the SHA-256 hash of the attestation public key bytes

@native
@apple
Scenario: Invalid challenge produces verification failure
    Given the SecurityFramework Apple interop is available on this platform
    When the provider generates a hardware-backed key via Apple Security.framework
    And the key is attested with a known challenge hash
    Then verifying the attestation against a different challenge hash fails
