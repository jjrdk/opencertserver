Feature: AMD SEV-SNP Attestation
  As a cloud operator
  I want to verify the identity of an AMD SEV-SNP enabled instance in Azure
  So that I can ensure the hardware is genuine before issuing certificates

  Scenario: End-to-end AMD attestation on Azure
    Given an active SEV-SNP enabled instance in Azure
    When we request a verified identity token
    Then the system should retrieve VCEK, verify via Root CA, and produce a signed report from https://amd-vps.confidentialcomputing.azure.com
