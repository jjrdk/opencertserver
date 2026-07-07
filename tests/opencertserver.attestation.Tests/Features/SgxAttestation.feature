Feature: Intel SGX Attestation
  As a cloud operator
  I want to verify the identity of an Intel SGX enclave in Azure
  So that I can ensure the hardware is genuine before issuing certificates

  Scenario: End-to-end Intel attestation on Azure
    Given an active SGX enclave in Azure
    When we request a verified identity token
    Then the system should retrieve PCK ID, fetch cert from https://pccs.confidentialcomputing.azure.com, verify via Root CA, and produce a signed quote
