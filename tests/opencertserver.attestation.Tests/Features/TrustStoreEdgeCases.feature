Feature: TrustStore Edge Cases
  As a security administrator
  I want the TrustStore to correctly validate certificate chains
  So that legitimate vendor certificates pass and all others fail

  Scenario: Certificate signed by pinned root is accepted
    Given the TrustStore has a pinned root CA for "Intel"
    And a device certificate signed by that pinned root CA
    When ValidateChain is called with vendor "Intel"
    Then the result should be valid

  Scenario: Self-signed certificate from different CA is rejected
    Given the TrustStore has a pinned root CA for "Intel"
    When a self-signed certificate from a different CA is validated for vendor "Intel"
    Then the chain validation should fail with "Untrusted Vendor Root"

  Scenario: Unknown vendor name returns error
    Given the TrustStore has a pinned root CA for "Intel"
    When a certificate is validated for vendor "UnknownVendor"
    Then the result should be invalid with error "Unknown Vendor"

  Scenario: TrustStore reports available pinned vendors
    Given the TrustStore has a pinned root CA for "Intel"
    And a pinned root CA for "AMD"
    When the pinned vendors are listed
    Then the list should contain "Intel"
    And the list should contain "AMD"
