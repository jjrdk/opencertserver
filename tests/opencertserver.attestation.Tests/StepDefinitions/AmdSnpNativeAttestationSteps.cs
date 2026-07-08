using System.Runtime.InteropServices;
using OpenCertServer.Attestation;
using OpenCertServer.Attestation.Native;
using Reqnroll;
using Xunit;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

/// <summary>
/// Tests that call the real <see cref="AmdSnpNativeInterop"/> — no mocks.
/// On non-Linux platforms the "not running on Linux" scenarios verify the platform guard.
/// On Linux without AMD SEV-SNP hardware/driver the library-missing path is exercised.
/// </summary>
[Binding]
[Scope(Feature = "AMD SEV-SNP Native Attestation")]
public sealed class AmdSnpNativeAttestationSteps
{
    private Exception? _thrownException;
    private string? _chipId;

    [Given(@"the AMD SNP native interop is attempted on this platform")]
    public void GivenAmdSnpInteropAttempted() { }

    [Given(@"this test is NOT running on Linux")]
    public void GivenNotRunningOnLinux()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            Assert.Skip("This scenario tests non-Linux behaviour; skipping when running on Linux.");
    }

    [When(@"the native AMD SNP provider tries to retrieve the VCEK ChipID")]
    public void WhenTryRetrieveVcekChipId()
    {
        var interop = new AmdSnpNativeInterop();
        IntPtr ptr = IntPtr.Zero;
        uint size = 0;
        try
        {
            int result = interop.GetVcekChipId(out ptr, ref size);
            if (result == AmdSnpErrorCodes.Success && ptr != IntPtr.Zero && size > 0)
            {
                var bytes = new byte[size];
                Marshal.Copy(ptr, bytes, 0, (int)size);
                _chipId = Convert.ToHexString(bytes);
            }
        }
        catch (Exception ex)
        {
            _thrownException = ex;
        }
    }

    [When(@"GetVcekChipId is called on AmdSnpNativeInterop")]
    public void WhenGetVcekChipIdCalledOnNonLinux()
    {
        var interop = new AmdSnpNativeInterop();
        IntPtr ptr = IntPtr.Zero;
        uint size = 0;
        try { interop.GetVcekChipId(out ptr, ref size); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [Then(@"either a non-empty hex ChipID is returned or a NativeLibraryException is thrown for ""(.*)""")]
    public void ThenChipIdOrNativeLibraryException(string libraryName)
    {
        if (_chipId is not null)
        {
            Assert.NotEmpty(_chipId);
        }
        else if (_thrownException is NativeLibraryException nle)
        {
            Assert.Equal(libraryName, nle.LibraryName);
        }
        else if (_thrownException is PlatformNotSupportedException)
        {
            // Running on non-Linux — acceptable on macOS CI
        }
        else if (_thrownException is AttestationException ae)
        {
            Assert.True(ae.ErrorCode != 0);
        }
        else if (_thrownException != null)
        {
            Assert.Fail($"Unexpected exception: {_thrownException.GetType().Name}: {_thrownException.Message}");
        }
        else
        {
            Assert.Fail("Expected either a ChipID result or an exception.");
        }
    }

    [Then(@"a PlatformNotSupportedException is thrown from the AMD interop")]
    public void ThenPlatformNotSupportedThrown()
    {
        Assert.NotNull(_thrownException);
        Assert.IsType<PlatformNotSupportedException>(_thrownException);
    }
}
