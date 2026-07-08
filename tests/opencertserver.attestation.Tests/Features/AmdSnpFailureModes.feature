Feature: AMD SEV-SNP Provider Failure Modes
  As a platform operator
  I want the AMD SNP provider to surface actionable errors
  So that missing hardware, drivers, or gateway failures are clearly diagnosed

  Scenario: Native AMD driver is not present
    Given the AMD SNP native driver is not installed
    When the provider attempts to retrieve the VCEK ChipID
    Then a NativeLibraryException is thrown with library name "amd_snp_driver"

  Scenario: Native AMD driver returns permission denied
    Given the AMD SNP native driver returns error code for permission denied
    When the provider attempts to retrieve the VCEK ChipID
    Then an AttestationException is thrown with vendor error name "SNP_ERROR_PERMISSION_DENIED"

  Scenario: VPS endpoint returns HTTP 503
    Given a configured AMD provider with a valid ChipID
    When the VPS endpoint returns HTTP 503
    Then a VendorApiException is thrown with HTTP status 503

  Scenario: VPS endpoint throws network exception
    Given a configured AMD provider with a valid ChipID
    When the VPS endpoint throws a network error
    Then a VendorApiException is thrown for vendor "AMD"

  Scenario: AMD report generation returns not-supported error
    Given the AMD SNP native driver returns error code for hardware not supported
    When the provider attempts to generate an attestation report
    Then an AttestationException is thrown with vendor error name "SNP_ERROR_NOT_SUPPORTED"
