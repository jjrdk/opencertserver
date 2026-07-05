Feature: Device Attest Challenge Models
  As an ACME server developer
  I want DeviceAttestChallengeAnswer to serialize and deserialize correctly
  And IValidateDeviceAttestChallenges to extend IValidateChallenges

  Scenario: DeviceAttestChallengeAnswer serializes correctly
    Given a DeviceAttestChallengeAnswer with Nonce "abc" Proof "xyz" AikCertificate "certdata" DeviceId "serial123"
    When serialized to JSON
    Then the JSON contains nonce "abc"
    And the JSON contains proof "xyz"
    And the JSON contains aikCertificate "certdata"
    And the JSON contains deviceId "serial123"

  Scenario: DeviceAttestChallengeAnswer deserializes from JSON correctly
    Given a JSON string with nonce "abc" proof "xyz" aikCertificate "certdata" deviceId "serial123"
    When deserialized to DeviceAttestChallengeAnswer
    Then the Nonce property is "abc"
    And the Proof property is "xyz"
    And the AikCertificate property is "certdata"
    And the DeviceId property is "serial123"

  Scenario: IValidateDeviceAttestChallenges extends IValidateChallenges
    When I inspect the IValidateDeviceAttestChallenges type via reflection
    Then it implements IValidateChallenges
