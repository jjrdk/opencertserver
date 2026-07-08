Feature: Global Attestation Service Cloud Context Mapping
  As a platform operator
  I want the GlobalAttestationService to correctly map cloud contexts to providers
  So that all combinations from the spec table 6.1 are supported

  Scenario: Azure context selects Intel provider by default
    Given the cloud context is "Azure" with no vendor preference
    When the AttestationService selects a provider
    Then the selected provider's VendorName should be "Intel"

  Scenario: Azure context with AMD vendor preference selects AMD provider
    Given the cloud context is "Azure" with vendor preference "AMD"
    When the AttestationService selects a provider
    Then the selected provider's VendorName should be "AMD"

  Scenario: AWS context selects Intel provider by default
    Given the cloud context is "AWS" with no vendor preference
    When the AttestationService selects a provider
    Then the selected provider's VendorName should be "Intel"

  Scenario: Client context selects Apple provider
    Given the cloud context is "Client" with no vendor preference
    When the AttestationService selects a provider
    Then the selected provider's VendorName should be "Apple"

  Scenario: Azure Intel endpoint is PCCS URL
    Given the cloud context is "Azure" with no vendor preference
    When the endpoint for vendor "Intel" is requested
    Then the endpoint should be "https://pccs.confidentialcomputing.azure.com"

  Scenario: AWS Intel endpoint is Nitro
    Given the cloud context is "AWS" with no vendor preference
    When the endpoint for vendor "Intel" is requested
    Then the endpoint should be "https://nitro-enclaves.us-east-1.amazonaws.com"

  Scenario: Unknown cloud context with no vendor preference throws
    Given the cloud context is "Unknown" with no vendor preference
    When the AttestationService tries to select a provider
    Then a NotSupportedException is thrown
