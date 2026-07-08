Feature: Intel SGX Provider Failure Modes
  As a platform operator
  I want the SGX provider to surface actionable errors
  So that missing hardware, libraries, or gateway failures are clearly diagnosed

  Scenario: Native SGX library is not present
    Given the SGX native library is not installed
    When the provider attempts to retrieve the PCK ID
    Then a NativeLibraryException is thrown with library name "sgx_dcap_ql"

  Scenario: Native SGX returns hardware error code
    Given the SGX native driver returns error code for hardware busy
    When the provider attempts to retrieve the PCK ID
    Then an AttestationException is thrown with vendor error name "SGX_ERROR_DEVICE_BUSY"

  Scenario: PCCS endpoint returns HTTP 403
    Given a configured SGX provider with a valid PCK ID
    When the PCCS endpoint returns HTTP 403
    Then a VendorApiException is thrown with HTTP status 403

  Scenario: PCCS endpoint times out
    Given a configured SGX provider with a valid PCK ID
    When the PCCS endpoint throws a network error
    Then a VendorApiException is thrown for vendor "Intel"

  Scenario: Certificate is served from cache on second request
    Given a configured SGX provider with a valid PCK ID
    And the PCCS endpoint returns a valid certificate for device "A1B2C3D4"
    When the certificate is requested twice for device "A1B2C3D4"
    Then the PCCS endpoint is called only once

  Scenario: SGX quote generation fails with out-of-memory
    Given the SGX native driver returns error code for out of memory during quote creation
    When the provider attempts to generate a quote
    Then an AttestationException is thrown with vendor error name "SGX_ERROR_OUT_OF_MEMORY"
