using System.Security.Cryptography;
using OpenCertServer.Tpm2Lib.Org.BouncyCastle.Crypto.Parameters;

namespace OpenCertServer.Tpm2Lib.Org.BouncyCastle.Crypto.Macs;

/// <summary>
/// Minimal AES-CMAC implementation compatible with the small subset used by
/// the vendored TSS.NET code (Init(KeyParameter), BlockUpdate, DoFinal, GetMacSize).
/// This implementation follows RFC 4493.
/// </summary>
public sealed class CMac
{
    private const int BlockSize = 16;
    private byte[] _key = [];
    private readonly MemoryStream _buffer = new();
    private byte[] _k1 = [];
    private byte[] _k2 = [];

    public void Init(KeyParameter param)
    {
        if (param == null)
        {
            throw new ArgumentNullException(nameof(param));
        }

        _key = param.GetKey();
        GenerateSubkeys();
        _buffer.SetLength(0);
    }

    public int GetMacSize() => BlockSize;

    public void BlockUpdate(byte[] input, int inOff, int len)
    {
        _buffer.Write(input, inOff, len);
    }

    public int DoFinal(byte[] outBuf, int outOff)
    {
        var msg = _buffer.ToArray();
        byte[] lastBlock;
        var lastBlockComplete = (msg.Length != 0) && (msg.Length % BlockSize == 0);

        if (msg.Length == 0)
        {
            // empty message -> single padded block
            var padded = new byte[BlockSize];
            padded[0] = 0x80;
            lastBlock = Xor(padded, _k2); // as per RFC when message is empty it's considered incomplete
        }
        else
        {
            var n = (msg.Length + BlockSize - 1) / BlockSize;
            var last = new byte[BlockSize];
            Array.Copy(msg, (n - 1) * BlockSize, last, 0, Math.Min(BlockSize, msg.Length - (n - 1) * BlockSize));

            if (lastBlockComplete)
            {
                lastBlock = Xor(last, _k1);
            }
            else
            {
                // pad
                var padded = new byte[BlockSize];
                var lastLen = msg.Length - (n - 1) * BlockSize;
                Array.Copy(last, 0, padded, 0, lastLen);
                padded[lastLen] = 0x80;
                lastBlock = Xor(padded, _k2);
            }
        }

        // CBC-MAC over all blocks
        var prev = new byte[BlockSize]; // zero IV
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = _key;

        using var encryptor = aes.CreateEncryptor();

        var numBlocks = (msg.Length + BlockSize - 1) / BlockSize;
        if (msg.Length == 0)
        {
            numBlocks = 0;
        }

        // process all but last block
        for (var i = 0; i < numBlocks - 1; i++)
        {
            var block = new byte[BlockSize];
            Array.Copy(msg, i * BlockSize, block, 0, BlockSize);
            var x = Xor(prev, block);
            var outb = new byte[BlockSize];
            encryptor.TransformBlock(x, 0, BlockSize, outb, 0);
            prev = outb;
        }

        // final
        var xFinal = Xor(prev, lastBlock);
        var finalOut = new byte[BlockSize];
        encryptor.TransformBlock(xFinal, 0, BlockSize, finalOut, 0);

        Array.Copy(finalOut, 0, outBuf, outOff, BlockSize);
        return BlockSize;
    }

    private static byte[] Xor(byte[] a, byte[] b)
    {
        var r = new byte[a.Length];
        for (var i = 0; i < a.Length; i++) r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    private void GenerateSubkeys()
    {
        // K1 = L << 1; if MSB(L) == 1 then K1 ^= Rb
        // K2 = K1 << 1; if MSB(K1) == 1 then K2 ^= Rb
        var l = new byte[BlockSize];
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = _key;
            using var enc = aes.CreateEncryptor();
            enc.TransformBlock(new byte[BlockSize], 0, BlockSize, l, 0);
        }

        _k1 = ShiftLeft(l);
        if ((l[0] & 0x80) != 0)
        {
            // Rb for 128-bit block is 0x87
            _k1[BlockSize - 1] ^= 0x87;
        }

        _k2 = ShiftLeft(_k1);
        if ((_k1[0] & 0x80) != 0)
        {
            _k2[BlockSize - 1] ^= 0x87;
        }
    }

    private static byte[] ShiftLeft(byte[] input)
    {
        var output = new byte[input.Length];
        byte overflow = 0;
        for (var i = input.Length - 1; i >= 0; i--)
        {
            var b = input[i];
            output[i] = (byte)((b << 1) | overflow);
            overflow = (byte)((b & 0x80) != 0 ? 1 : 0);
        }
        return output;
    }
}
