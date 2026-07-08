Feature: AMD SEV-SNP Native Attestation
  As a platform operator on AMD SEV-SNP hardware
  I want the AMD SNP provider to call amd_snp_driver natively
  So that the VCEK ChipID comes from real hardware, not a mock

  @native @amd
  Scenario: Attempt ChipID retrieval using real amd_snp_driver
    Given the AMD SNP native interop is attempted on this platform
    When the native AMD SNP provider tries to retrieve the VCEK ChipID
    Then either a non-empty hex ChipID is returned or a NativeLibraryException is thrown for "amd_snp_driver"

  @native @amd
  Scenario: AMD SNP provider on non-Linux platform throws PlatformNotSupportedException
    Given this test is NOT running on Linux
    When GetVcekChipId is called on AmdSnpNativeInterop
    Then a PlatformNotSupportedException is thrown from the AMD interop
