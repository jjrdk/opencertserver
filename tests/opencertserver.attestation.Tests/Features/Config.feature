Feature: Load cloud-specific endpoints
  Scenario: Load cloud-specific endpoints
    Given a config file specifying "Azure" as the context
    When the AttestationService initializes
    Then it should select https://pccs.confidentialcomputing.azure.com as the Intel SGX endpoint
