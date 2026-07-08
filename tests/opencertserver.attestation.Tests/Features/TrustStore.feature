Feature: Global Trust Root and Revocation
  As a security administrator
  I want to verify trust chains against pinned root certificates
  So that forged vendor certificates are rejected

  Scenario: Reject forged vendor certificate
    Given a device certificate not signed by a pinned Root CA
    When running ValidateChain()
    Then it must return false with "Untrusted Vendor Root" error
