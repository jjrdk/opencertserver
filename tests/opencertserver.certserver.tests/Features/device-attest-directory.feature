Feature: Device Attest Directory Advertisement
  As an ACME client
  I want the server directory to advertise supported challenge types
  So that I know device-attest-01 is available

  Scenario: Directory advertises device-attest-01 in metadata
    Given an initialized ACME server with device-attest-01 wired up
    When I GET the directory endpoint
    Then the response contains a meta field
    And the challengeTypesWithAdditionalContent array includes "device-attest-01"

  Scenario: Directory also advertises http-01 in metadata
    Given an initialized ACME server with device-attest-01 wired up
    When I GET the directory endpoint
    Then the challengeTypesWithAdditionalContent array includes "http-01"

  Scenario: Directory also advertises dns-01 in metadata
    Given an initialized ACME server with device-attest-01 wired up
    When I GET the directory endpoint
    Then the challengeTypesWithAdditionalContent array includes "dns-01"
