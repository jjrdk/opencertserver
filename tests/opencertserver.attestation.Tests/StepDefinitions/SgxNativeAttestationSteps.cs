using System.Runtime.InteropServices;
using OpenCertServer.Attestation;
using OpenCertServer.Attestation.Native;
using Reqnroll;
using Xunit;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

/// <summary>
/// Tests that call the real <see cref="SgxNativeInterop"/> — no mocks.
/// On non-Linux platforms the "not running on Linux" scenarios verify the platform guard.
/// On Linux without SGX hardware/driver the library-missing path is exercised.
/// Only on actual SGX hardware would the full happy path run.
/// </summary>
[Binding]
[Scope(Feature = "Intel SGX Native Attestation")]
public sealed class SgxNativeAttestationSteps
{
    private Exception? _thrownException;
    private string? _pckId;

    [Given(@"the Intel SGX native interop is attempted on this platform")]
    public void GivenSgxInteropAttempted()
    {
        // This step always proceeds regardless of platform.
        // The When step will determine what happens.
    }

    [Given(@"this test is NOT running on Linux")]
    public void GivenNotRunningOnLinux()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            Assert.Skip("This scenario tests non-Linux behaviour; skipping when running on Linux.");
    }

    [When(@"the native SGX provider tries to retrieve the PCK ID")]
    public void WhenTryRetrievePckId()
    {
        var interop = new SgxNativeInterop();
        IntPtr ptr = IntPtr.Zero;
        uint size = 0, tcb = 0;
        try
        {
            int result = interop.GetPckId(out ptr, ref size, ref tcb);
            if (result == SgxErrorCodes.Success && ptr != IntPtr.Zero && size > 0)
            {
                var bytes = new byte[size];
                Marshal.Copy(ptr, bytes, 0, (int)size);
                _pckId = Convert.ToHexString(bytes);
            }
        }
        catch (Exception ex)
        {
            _thrownException = ex;
        }
    }

    [When(@"GetPckId is called on SgxNativeInterop")]
    public void WhenGetPckIdCalledOnNonLinux()
    {
        var interop = new SgxNativeInterop();
        IntPtr ptr = IntPtr.Zero;
        uint size = 0, tcb = 0;
        try { interop.GetPckId(out ptr, ref size, ref tcb); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [Then(@"either a non-empty hex PCK ID is returned or a NativeLibraryException is thrown for ""(.*)""")]
    public void ThenPckIdOrNativeLibraryException(string libraryName)
    {
        if (_pckId is not null)
        {
            // We're on real SGX hardware
            Assert.NotEmpty(_pckId);
        }
        else if (_thrownException is NativeLibraryException nle)
        {
            Assert.Equal(libraryName, nle.LibraryName);
        }
        else if (_thrownException is PlatformNotSupportedException)
        {
            // Running on non-Linux — acceptable on e.g. macOS CI
        }
        else if (_thrownException is AttestationException ae)
        {
            // Hardware present but specific error code — still a valid SGX native call
            Assert.True(ae.ErrorCode != 0);
        }
        else if (_thrownException != null)
        {
            Assert.Fail($"Unexpected exception: {_thrownException.GetType().Name}: {_thrownException.Message}");
        }
        else
        {
            Assert.Fail("Expected either a PCK ID result or an exception.");
        }
    }

    [Then(@"a PlatformNotSupportedException is thrown from the SGX interop")]
    public void ThenPlatformNotSupportedThrown()
    {
        Assert.NotNull(_thrownException);
        Assert.IsType<PlatformNotSupportedException>(_thrownException);
    }
}
