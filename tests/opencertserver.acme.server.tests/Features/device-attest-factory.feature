Feature: Device Attest Challenge Factory Routing
  As an ACME server
  I want the challenge validator factory to route device-attest-01 challenges correctly
  So that the right validator handles each challenge type

  Scenario: GetValidator routes to DeviceAttest validator for device-attest-01 type
    Given the challenge validator factory is initialized with all three validators
    When I request the validator for a device-attest-01 challenge
    Then the returned validator implements IValidateDeviceAttestChallenges

  Scenario: GetValidator routes to Http01 validator for http-01 type
    Given the challenge validator factory is initialized with all three validators
    When I request the validator for a http-01 challenge
    Then the returned validator implements IValidateHttp01Challenges

  Scenario: GetValidator routes to Dns01 validator for dns-01 type
    Given the challenge validator factory is initialized with all three validators
    When I request the validator for a dns-01 challenge
    Then the returned validator implements IValidateDns01Challenges

  Scenario: GetValidator throws for unknown challenge type
    Given the challenge validator factory is initialized with all three validators
    When I request the validator for an unknown challenge type
    Then an InvalidOperationException is thrown with message "Unknown Challenge Type"
