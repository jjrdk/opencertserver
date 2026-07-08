using System.Runtime.InteropServices;

namespace OpenCertServer.Attestation.Native;

/// <summary>
/// Low-level P/Invoke bindings for Apple CoreFoundation and Security frameworks.
/// All methods guard against non-macOS platforms — callers must check <see cref="OperatingSystem.IsMacOS()"/>
/// before invoking.
/// </summary>
internal static partial class AppleCF
{
    private const string CF = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

    private const uint kCFStringEncodingUTF8 = 0x08000100;
    private const long kCFNumberIntType = 9; // CFNumberType.kCFNumberIntType

    // Lazy-load the proper CF callback pointers (required for CFDictionaryCreateMutable).
    // These symbols are exported from CoreFoundation as data symbols (structs in the library).
    private static readonly Lazy<(IntPtr Key, IntPtr Value)> _cfTypeCallbacks =
        new(() =>
        {
            var lib = NativeLibrary.Load(CF);
            return (
                NativeLibrary.GetExport(lib, "kCFTypeDictionaryKeyCallBacks"),
                NativeLibrary.GetExport(lib, "kCFTypeDictionaryValueCallBacks")
            );
        });

    // ── CoreFoundation ───────────────────────────────────────────────────────

    [LibraryImport(CF)]
    private static partial IntPtr CFStringCreateWithCString(
        IntPtr allocator,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string cStr,
        uint encoding);

    [LibraryImport(CF)]
    private static partial IntPtr CFNumberCreate(IntPtr allocator, long theType, ref int value);

    [LibraryImport(CF)]
    private static partial IntPtr CFDictionaryCreateMutable(
        IntPtr allocator, nint capacity, IntPtr keyCallBacks, IntPtr valueCallBacks);

    [LibraryImport(CF)]
    private static partial void CFDictionarySetValue(IntPtr dict, IntPtr key, IntPtr value);

    [LibraryImport(CF)]
    private static partial IntPtr CFDataCreate(IntPtr allocator, byte[] bytes, nint length);

    [LibraryImport(CF)]
    private static partial IntPtr CFDataGetBytePtr(IntPtr data);

    [LibraryImport(CF)]
    private static partial nint CFDataGetLength(IntPtr data);

    [LibraryImport(CF)]
    internal static partial void CFRelease(IntPtr cf);

    /// <summary>Copies a CFString into a managed string (for error messages).</summary>
    [LibraryImport(CF)]
    private static partial IntPtr CFCopyDescription(IntPtr cf);

    [LibraryImport(CF)]
    private static partial nint CFStringGetLength(IntPtr theString);

    [LibraryImport(CF)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CFStringGetCString(
        IntPtr theString, Span<byte> buffer, nint bufferSize, uint encoding);

    // ── Public helpers ────────────────────────────────────────────────────────

    /// <summary>Creates a CFString (caller must CFRelease).</summary>
    internal static IntPtr MakeCFString(string s) =>
        CFStringCreateWithCString(IntPtr.Zero, s, kCFStringEncodingUTF8);

    /// <summary>Creates a CFNumber from an int (caller must CFRelease).</summary>
    internal static IntPtr MakeCFInt(int v) =>
        CFNumberCreate(IntPtr.Zero, kCFNumberIntType, ref v);

    /// <summary>Creates a CFData from a managed byte array (caller must CFRelease).</summary>
    internal static IntPtr MakeCFData(byte[] bytes) =>
        CFDataCreate(IntPtr.Zero, bytes, bytes.Length);

    /// <summary>Copies bytes from a CFData into a managed array.</summary>
    internal static byte[] CFDataToBytes(IntPtr data)
    {
        if (data == IntPtr.Zero) return [];
        nint len = CFDataGetLength(data);
        if (len <= 0) return [];
        var buf = new byte[len];
        IntPtr ptr = CFDataGetBytePtr(data);
        Marshal.Copy(ptr, buf, 0, (int)len);
        return buf;
    }

    /// <summary>Returns a human-readable description of a CF object (for error logging).</summary>
    internal static string DescribeCF(IntPtr cf)
    {
        if (cf == IntPtr.Zero) return "(null)";
        var desc = CFCopyDescription(cf);
        if (desc == IntPtr.Zero) return "(no description)";
        try
        {
            nint len = CFStringGetLength(desc);
            var buf = new byte[(len + 1) * 4];
            CFStringGetCString(desc, buf, buf.Length, kCFStringEncodingUTF8);
            return System.Text.Encoding.UTF8.GetString(buf).TrimEnd('\0');
        }
        finally { CFRelease(desc); }
    }

    /// <summary>
    /// Builds a CFDictionary suitable for SecKeyCreateRandomKey.
    /// Uses proper <c>kCFTypeDictionaryKeyCallBacks/ValueCallBacks</c> to ensure
    /// the dictionary retains its keys and values correctly.
    /// All allocations are added to <paramref name="lease"/> so the caller can CFRelease them
    /// after the native call completes.
    /// </summary>
    internal static IntPtr MakeKeyGenParams(bool useSecureEnclave, List<IntPtr> lease)
    {
        var (keyCallbacks, valueCallbacks) = _cfTypeCallbacks.Value;

        var dict = CFDictionaryCreateMutable(IntPtr.Zero, 0, keyCallbacks, valueCallbacks);
        lease.Add(dict);

        // kSecAttrKeyType = "type" ; value = kSecAttrKeyTypeECSECPrimeRandom = "73"
        var k1 = MakeCFString("type"); lease.Add(k1);
        var v1 = MakeCFString("73"); lease.Add(v1);
        CFDictionarySetValue(dict, k1, v1);

        // kSecAttrKeySizeInBits = "bsiz" = 256
        var k2 = MakeCFString("bsiz"); lease.Add(k2);
        var v2 = MakeCFInt(256); lease.Add(v2);
        CFDictionarySetValue(dict, k2, v2);

        if (useSecureEnclave)
        {
            // kSecAttrTokenID = "tkid" = kSecAttrTokenIDSecureEnclave = "com.apple.setoken"
            var k3 = MakeCFString("tkid"); lease.Add(k3);
            var v3 = MakeCFString("com.apple.setoken"); lease.Add(v3);
            CFDictionarySetValue(dict, k3, v3);
        }

        return dict;
    }
}

/// <summary>
/// P/Invoke bindings for the Apple Security framework (macOS / iOS).
/// </summary>
internal static partial class AppleSecurity
{
    private const string Sec = "/System/Library/Frameworks/Security.framework/Security";

    [LibraryImport(Sec)]
    internal static partial IntPtr SecKeyCreateRandomKey(IntPtr parameters, out IntPtr error);

    [LibraryImport(Sec)]
    internal static partial IntPtr SecKeyCopyPublicKey(IntPtr key);

    [LibraryImport(Sec)]
    internal static partial IntPtr SecKeyCopyExternalRepresentation(IntPtr key, out IntPtr error);

    [LibraryImport(Sec)]
    internal static partial IntPtr SecKeyCreateSignature(
        IntPtr key, IntPtr algorithm, IntPtr dataToSign, out IntPtr error);
}
