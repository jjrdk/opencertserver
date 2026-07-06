Feature: Device Attestation ACME Challenge Types
    As a device identity platform operator
    I want device-attest-01 to be recognized as a valid challenge type
    So that clients can opt for hardware-backed attestation instead of domain validation

Scenario: DeviceAttest01 is included in all supported types
    When I enumerate the supported challenge types via ChallengeTypes.AllTypes
    Then the collection must contain "http-01"
    And the collection must contain "dns-01"
    And the collection must contain "device-attest-01"

Scenario: Client receives a device-attest-01 challenge for CA-provisioned orders
    Given an ACME client has registered with the server and created a new order
    When the order is authorized for certificate issuance
    Then the authorization must include at least one challenge of type "device-attest-01"
