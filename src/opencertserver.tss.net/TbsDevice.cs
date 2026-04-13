/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace OpenCertServer.Tpm2Lib;

public sealed class TbsDevice : Tpm2Device
{
    private UIntPtr _tbsHandle;
    private UIntPtr _originalHandle;

    /// <summary>
    /// Default constructor.
    /// </summary>
    public TbsDevice(bool hasRm = true)
    {
        NeedsHMAC = false;
        _HasRM = hasRm;
    }

    public override UIntPtr GetHandle(UIntPtr h)
    {
        if (h != UIntPtr.Zero)
        {
            _tbsHandle = h;
        }
        return _tbsHandle;
    }

    public override void Connect()
    {
        TbsWrapper.TbsContextParams contextParams;

        var tbsContext = UIntPtr.Zero;
        contextParams.Version = TbsWrapper.TbsContextVersion.Two;
        contextParams.Flags = TbsWrapper.TbsContextCreateFlags.IncludeTpm20;
        var result = TbsWrapper.NativeMethods
            .Tbsi_Context_Create(ref contextParams, ref tbsContext);
        Debug.WriteLine(Globs.GetResourceString("TbsHandle:") + tbsContext.ToUInt32());

        if (result != TbsWrapper.TbsResult.Success)
        {
            throw new Exception("Failed to create TBS context: Error {" + result + "}");
        }

        _tbsHandle = tbsContext;
        _originalHandle = tbsContext;
    }

    public override void Close()
    {
        if (_originalHandle != UIntPtr.Zero)
        {
            TbsWrapper.NativeMethods.Tbsip_Context_Close(_originalHandle);
            _originalHandle = UIntPtr.Zero;
        }
    }

    public override void PowerCycle()
    {
        throw new Exception("TbsDevice does not implement PowerCycle()");
    }

    public override void AssertPhysicalPresence(bool assertPhysicalPresence)
    {
        throw new NotImplementedException("Device does not support PP");
    }

    public override bool PlatformAvailable()
    {
        return false;
    }

    public override bool PowerCtlAvailable()
    {
        return false;
    }

    public override bool LocalityCtlAvailable()
    {
        return false;
    }

    public override bool NvCtlAvailable()
    {
        return false;
    }

    public override bool UsesTbs()
    {
        return true;
    }

    public override bool HasRM()
    {
        // TODO: detect raw mode during class initialization
        return _HasRM;
    }

    public override void DispatchCommand(CommandModifier active, byte[] inBuf, out byte[] outBuf)
    {
        if (_tbsHandle == UIntPtr.Zero)
        {
            throw new Exception("TBS context not created.");
        }

        var resultBuf = new byte[4096];
        var resultByteCount = (uint)resultBuf.Length;
        var result = TpmRc.Success;
        var tbsRes = TbsWrapper.NativeMethods.
            Tbsip_Submit_Command(_tbsHandle,
                (TbsWrapper.TbsCommandLocality)active.ActiveLocality,
                active.ActivePriority,
                inBuf,
                (uint)inBuf.Length,
                resultBuf,
                ref resultByteCount);
        if (tbsRes == TbsWrapper.TbsResult.Success)
        {
            if (resultByteCount != 0)
            {
                outBuf = new byte[resultByteCount];
                Array.Copy(resultBuf, outBuf, (int)resultByteCount);
                return;
            }
            result = TpmRc.TbsUnknownError;
        }
        else
        {
            result = (TpmRc)tbsRes;
        }

        outBuf = TpmErrorHelpers.BuildErrorResponseBuffer(result);
    } // TbsDevice.DispatchCommand

    protected override void Dispose(bool disposing)
    {
        Close();
    }

    public override bool ImplementsCancel()
    {
        return true;
    }

    public override void SignalCancelOn()
    {
        CancelContext();
    }

    public override void SignalCancelOff()
    {
    }

    public override void CancelContext()
    {
        var result = TbsWrapper.NativeMethods.Tbsip_Cancel_Commands(_tbsHandle);
        if (result != TbsWrapper.TbsResult.Success)
        {
            Debug.WriteLine("TbsStubs.Tbsip_Cancel_Command error 0x{0:x}", result);
            throw new Exception("Tbsip_Cancel_Command() failed. Error {" + result + "}");
        }
    }
    private byte[] GetTpmAuth(TbsAuthType authType)
    {
#if false
            return new byte[0];
#else
        if (_tbsHandle == UIntPtr.Zero)
        {
            throw new Exception("TBS context not created.");
        }

        //Console.WriteLine("GetTpmAuth: Retrieving auth value {0}", authType);
        var resultBuf = new byte[256];
        var resultByteCount = (uint)resultBuf.Length;
        var result = TbsWrapper.NativeMethods.
            Tbsi_Get_OwnerAuth(_tbsHandle,
                (uint)authType,
                resultBuf,
                ref resultByteCount);
        if (result != TbsWrapper.TbsResult.Success)
        {
#if false
                Console.WriteLine($"Trying to read LockoutAuth from the registry...");
                try
                {
                    string lockoutAuthBase64 = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM\WMI\Admin", "LockoutHash", null);
                    if (lockoutAuthBase64 != null)
                    {
                        resultBuf = Convert.FromBase64String(lockoutAuthBase64);
                        Console.WriteLine($"LockoutAuth: {lockoutAuthBase64} | len {resultBuf.Length} bytes | {Globs.HexFromByteArray(resultBuf)}");
                        return resultBuf;
                    }
                }
                catch (Exception e) {
                    Console.WriteLine($"Exception: {e}");
                }
#endif
#if !WINDOWS_UWP
            Console.WriteLine("GetTpmAuth({0}): Windows TBS returned 0x{1:X} {2}", authType, result,
                result == TbsWrapper.TbsResult.OwnerauthNotFound ? " (OWNERAUTH_NOT_FOUND)" :
                result == TbsWrapper.TbsResult.BadParameter ? " (BAD_PARAMETER)" : "");
#endif
            return [];
        }

        return Globs.CopyData(resultBuf, 0, (int)resultByteCount);
#endif
    }

    public override byte[] GetLockoutAuth()
    {
        return GetTpmAuth(TbsAuthType.Lockout);
    }

    public override byte[] GetOwnerAuth()
    {
        return GetTpmAuth(TbsAuthType.Owner);
    }

    public override byte[] GetEndorsementAuth()
    {
        return GetTpmAuth(TbsAuthType.Endorsement);
    }
} // class TbsDevice

[SuppressMessage("Microsoft.Design", "CA1008:EnumsShouldHaveZeroValue")]
public enum TbsCommandPriority : uint
{
    Low = 100,
    Normal = 200,
    High = 300,
    System = 400,
    Max = 0x80000000
}

public enum TbsAuthType : uint
{
    Lockout = 1,        // TBS_OWNERAUTH_TYPE_FULL
    Endorsement = 12,   // TBS_OWNERAUTH_TYPE_ENDORSEMENT_20
    Owner = 13          // TBS_OWNERAUTH_TYPE_STORAGE_20
}

internal class TbsWrapper
{
    public class NativeMethods
    {
        // Note that code gen adds error code than can be returned by TBS API
        // to the TpmRc enum.

        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TbsResult
            Tbsi_Context_Create(
            ref TbsContextParams  contextParams,
            ref UIntPtr             context
            );

        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TbsResult
            Tbsi_Get_OwnerAuth(
            UIntPtr                 hContext,
            uint                    ownerAuthType,
            [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 3), Out]
            byte[]                  outBuf,
            ref uint                outBufLen
            );

        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TbsResult
            Tbsip_Context_Close(
            UIntPtr                 context
            );

        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TbsResult
            Tbsip_Submit_Command(
            UIntPtr                 context,
            TbsCommandLocality    locality,
            TbsCommandPriority priority,
            [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4), In]
            byte[]                  inBuffer,
            uint                    inBufferSize,
            [System.Runtime.InteropServices.MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6), Out]
            byte[]                  outBuf,
            ref uint                outBufLen
            );

        [DllImport("tbs.dll", CharSet = CharSet.Unicode)]
        internal static extern TbsResult
            Tbsip_Cancel_Commands(
            UIntPtr                 context
            );

    }

    public enum TbsResult : uint
    {
        Success = 0,
        OwnerauthNotFound = 0x80284015,
        BadParameter = 0x80284002
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TbsContextParams
    {
        public TbsContextVersion Version;
        public TbsContextCreateFlags Flags;
    }

    public enum TbsCommandLocality : uint
    {
        Zero = 0,
        One = 1,
        Two = 2,
        Three = 3,
        Four = 4
    }

    public enum TbsContextVersion : uint
    {
        One = 1,
        Two = 2
    }

    public enum TbsTpmVersion : uint
    {
        Invalid = 0,
        V12 = 1,
        V2 = 2
    }

    public enum TbsContextCreateFlags : uint
    {
        RequestRaw = 0x00000001,
        IncludeTpm12 = 0x00000002,
        IncludeTpm20 = 0x00000004
    }
} // class TbsWrapper

#if !WINDOWS_UWP
internal class TpmDllWrapper
{
    public class NativeMethods
    {
        // helper to find the TPM
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetDllDirectory(string lpPathName);

        [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void _TPM_Init();

        [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void TPM_Manufacture();

        [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void ExecuteCommand(
            uint requestSize,
            [In] byte[] request,
            ref uint responseSize,
            ref IntPtr response);

        [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void Signal_Hash_Start();

        [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void Signal_Hash_Data(uint size, byte[] buffer);

        [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void Signal_Hash_End();

        const string Platform = "tpm.dll"; // "platform.dll";

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__Signal_PhysicalPresenceOn();

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__Signal_PhysicalPresenceOff();

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__Signal_PowerOn();

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__Signal_PowerOff();

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__SetCancel();

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__ClearCancel();

        [DllImport("tpm.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__NVEnable(IntPtr platParm);

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__NVDisable();

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__RsaKeyCacheControl(int state);

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__LocalitySet(byte locality);

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__SetNvAvail();

        [DllImport(Platform, CallingConvention = CallingConvention.Cdecl)]
        public static extern void _plat__ClearNvAvail();
    }
} // class TpmDllWrapper

/// <summary>
/// The InprocTpm loads/runs TPM.dll (and ancillary libraries) in the TPM tester process.
/// </summary>
public sealed class InprocTpm : Tpm2Device
{
    private IntPtr _responseBuf;
    private uint _responseBufSize = 4096;

    /// <summary>
    /// Specify the path to TPM.dll.  Note: any TPM in the current directory takes precedence
    /// </summary>
    /// <param name="tpmDllPath"></param>
    public InprocTpm(string tpmDllPath)
    {
        TpmDllWrapper.NativeMethods.SetDllDirectory(tpmDllPath);
        TpmDllWrapper.NativeMethods._plat__NVEnable(IntPtr.Zero);
        NeedsHMAC = false;
        _responseBuf = Marshal.AllocHGlobal((int)_responseBufSize);
    }

    public override void Connect()
    {
        TpmDllWrapper.NativeMethods._plat__NVEnable(IntPtr.Zero);
        TpmDllWrapper.NativeMethods.TPM_Manufacture();
        TpmDllWrapper.NativeMethods._plat__NVDisable();
    }

    public override void Close()
    {
    }

    public override void PowerCycle()
    {
        PowerOff();
        PowerOn();
    }

    private bool _powerIsOn;

    public void PowerOff()
    {
        if (!_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods._plat__Signal_PowerOff();
        _powerIsOn = false;
    }

    public void PowerOn()
    {
        if (_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods._plat__Signal_PowerOn();
        TpmDllWrapper.NativeMethods._TPM_Init();
        TpmDllWrapper.NativeMethods._plat__SetNvAvail();
        _powerIsOn = true;
    }

    public override bool PlatformAvailable()
    {
        return true;
    }

    public override bool PowerCtlAvailable()
    {
        return true;
    }

    public override bool LocalityCtlAvailable()
    {
        return true;
    }

    public override bool NvCtlAvailable()
    {
        return true;
    }

    public override bool HasRM()
    {
        return _HasRM;
    }

    public override bool ImplementsPhysicalPresence()
    {
        return true;
    }

    public override void AssertPhysicalPresence(bool assertPhysicalPresence)
    {
        if (!_powerIsOn)
        {
            return;
        }
        if (assertPhysicalPresence)
        {
            TpmDllWrapper.NativeMethods._plat__Signal_PhysicalPresenceOn();
        }
        else
        {
            TpmDllWrapper.NativeMethods._plat__Signal_PhysicalPresenceOff();

        }
    }

    public override bool ImplementsCancel()
    {
        return true;
    }

    public override void SignalCancelOn()
    {
        if (!_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods._plat__SetCancel();
    }

    public override void SignalCancelOff()
    {
        if (!_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods._plat__ClearCancel();
    }

    public override void SignalNvOn()
    {
        if (!_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods._plat__NVEnable(IntPtr.Zero);
    }

    public override void SignalNvOff()
    {
        if (!_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods._plat__NVDisable();
    }

    public override void SignalKeyCacheOn()
    {
        if (!_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods._plat__RsaKeyCacheControl(1);
    }

    public override void SignalKeyCacheOff()
    {
        if (!_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods._plat__RsaKeyCacheControl(0);
    }

    public override void SignalHashStart()
    {
        if (!_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods.Signal_Hash_Start();
    }

    public override void SignalHashData(byte[] data)
    {
        if (!_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods.Signal_Hash_Data((uint)data.Length, data);
    }

    public override void SignalHashEnd()
    {
        if (!_powerIsOn)
        {
            return;
        }
        TpmDllWrapper.NativeMethods.Signal_Hash_End();
    }

    public override void TestFailureMode()
    {
        throw new NotImplementedException("Signal TestFailureMode is supported only by TPM simulator");
    }

    public override void DispatchCommand(CommandModifier active, byte[] inBuf, out byte[] outBuf)
    {
        if (!_powerIsOn)
        {
            outBuf = [];
            return;
        }
        var respSize = _responseBufSize;
        var respBuf = _responseBuf;

        TpmDllWrapper.NativeMethods._plat__LocalitySet(active.ActiveLocality);
        TpmDllWrapper.NativeMethods.ExecuteCommand((uint)inBuf.Length,
            inBuf,
            ref respSize,
            ref respBuf);
        outBuf = new byte[respSize];
        Marshal.Copy(respBuf, outBuf, 0, (int)respSize);
    }

    protected override void Dispose(bool disposing)
    {
        Close();
    }
} // class InprocTpm
#endif //WINDOWS_UWP
