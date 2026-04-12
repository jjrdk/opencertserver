namespace OpenCertServer.Tpm2Lib.Org.BouncyCastle.Crypto.Parameters;

/// <summary>Minimal KeyParameter shim for AES keys used by the vendored TSS.NET code.
/// This is a lightweight replacement for the BouncyCastle KeyParameter class.
/// </summary>
public sealed class KeyParameter
{
    private readonly byte[] key;

    public KeyParameter(byte[] key)
    {
        this.key = (byte[])key.Clone();
    }

    public byte[] GetKey() => (byte[])key.Clone();
}