Feature: Intel SGX Native Attestation
  As a platform operator on SGX hardware
  I want the SGX provider to call libsgx_dcap_ql natively
  So that the PCK ID comes from real hardware, not a mock

  @native @sgx
  Scenario: Attempt PCK ID retrieval using real libsgx_dcap_ql
    Given the Intel SGX native interop is attempted on this platform
    When the native SGX provider tries to retrieve the PCK ID
    Then either a non-empty hex PCK ID is returned or a NativeLibraryException is thrown for "sgx_dcap_ql"

  @native @sgx
  Scenario: SGX provider on non-Linux platform throws PlatformNotSupportedException
    Given this test is NOT running on Linux
    When GetPckId is called on SgxNativeInterop
    Then a PlatformNotSupportedException is thrown from the SGX interop
