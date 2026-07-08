Feature: Apple Secure Enclave Provider Failure Modes
  As a platform operator
  I want the Apple SE provider to behave correctly across platforms and error conditions
  So that invalid attestation objects and cross-platform usage are safely rejected

  Scenario: Empty attestation object is rejected
    Given the Apple SE provider is configured for server-side verification
    When the provider receives an empty attestation object
    Then an ArgumentException is thrown

  Scenario: Apple verification server returns HTTP 400
    Given the Apple SE provider is configured for server-side verification
    When the Apple verification server returns HTTP 400 with body "invalid attestation"
    Then a VendorApiException is thrown with HTTP status 400

  Scenario: Apple verification server is unreachable
    Given the Apple SE provider is configured for server-side verification
    When the Apple verification server throws a network error
    Then a VendorApiException is thrown for vendor "Apple"

  Scenario: Native key generation fails on Apple device
    Given the Apple SE provider runs on an Apple device with a failing native interop
    When the provider attempts to generate a device key
    Then an AttestationException is thrown

  Scenario: Request for device ID on non-Apple platform throws PlatformNotSupportedException
    Given the Apple SE provider is configured for server-side verification
    And the native interop is unavailable on this platform
    When the provider's GetDeviceIdAsync is called directly
    Then a PlatformNotSupportedException is thrown
