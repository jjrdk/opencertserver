Feature: TPM CA Key Provisioning
  As a CA server operator
  I want TPM-backed CA keys to be provisioned once and reused across restarts
  So that the private key never leaves the TPM hardware

  Scenario: RSA key is provisioned at first startup and reused on subsequent startups
    When I provision an RSA key at handle 0x81010001
    Then the RSA key should exist at handle 0x81010001
    When I provision an RSA key at handle 0x81010001 again
    Then only one key should exist at handle 0x81010001

  Scenario: ECDsa key is provisioned at first startup and reused on subsequent startups
    When I provision an ECDsa key at handle 0x81010002
    Then the ECDsa key should exist at handle 0x81010002
    When I provision an ECDsa key at handle 0x81010002 again
    Then only one key should exist at handle 0x81010002

  Scenario: RSA sign and verify round-trip
    Given an RSA key is provisioned at handle 0x81010001
    When I sign "hello TPM" with the RSA key at handle 0x81010001
    Then the signature should verify against the RSA public key at handle 0x81010001

  Scenario: ECDsa sign and verify round-trip
    Given an ECDsa key is provisioned at handle 0x81010002
    When I sign "hello TPM" with the ECDsa key at handle 0x81010002
    Then the signature should verify against the ECDsa public key at handle 0x81010002

  Scenario: TPM RSA profile factory creates a self-signed CA certificate
    When I create an RSA CA profile named "default" via TpmCaProfileFactory
    Then the profile certificate should be a CA certificate
    And the profile private key should be a TpmRsa instance

  Scenario: TPM ECDsa profile factory creates a self-signed CA certificate
    When I create an ECDsa CA profile named "ecdsa" via TpmCaProfileFactory
    Then the profile certificate should be a CA certificate
    And the profile private key should be a TpmEcDsa instance

  Scenario: Rollover produces OldWithOld, OldWithNew, and NewWithOld certificates
    Given an RSA CA profile named "default" has been created
    When I roll over to a new RSA CA certificate
    Then the published chain should contain 4 certificates
    And the published chain should contain the new active certificate
    And the published chain should contain the old certificate (OldWithOld)

