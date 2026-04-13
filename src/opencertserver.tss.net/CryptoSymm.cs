/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System.Diagnostics;
using System.Security.Cryptography;

namespace OpenCertServer.Tpm2Lib;

/// <summary>
/// A helper class for doing symmetric cryptography based on
/// TPM structure definitions.
/// </summary>
public sealed class SymCipher : IDisposable
{
    // .Net crypto object implementing the symmetric algorithm
    private readonly SymmetricAlgorithm _alg;

    // The block cipher mode requested by the user.
    // Since various .Net SDKs do not support some widely used block modes (e.g. CFB),
    // this class emulates them by using Alg in ECB mode.
    private readonly CipherMode _mode;

    public byte[] KeyData { get { return _alg.Key; } }

    /// <summary>
    /// Block size in bytes.
    /// </summary>
    public int BlockSize { get { return _alg.BlockSize / 8; } }

    /// <summary>
    /// Initialization vector size in bytes.
    /// </summary>
    public int IvSize { get { return _alg.IV.Length; } }

    private SymCipher(SymmetricAlgorithm alg, CipherMode mode)
    {
        _alg = alg;
        _mode = mode;
    }

    /// <summary>
    /// Block size in bytes.
    /// </summary>
    public static implicit operator byte[] (SymCipher sym)
    {
        return sym?.KeyData;
    }

    public static int GetBlockSize(SymDefObject symDef)
    {
        if (symDef.Algorithm == TpmAlgId.Tdes)
        {
            return 8;
        }
        if (symDef.Algorithm != TpmAlgId.Aes)
        {
            throw new ArgumentException("Unsupported algorithm " + symDef.Algorithm);
        }
        return 16;
    }

    /// <summary>
    /// Create a new SymCipher object with a random key based on the alg and mode supplied.
    /// </summary>
    /// <param name="symDef"></param>
    /// <param name="keyData"></param>
    /// <param name="iv"></param>
    /// <returns></returns>
    public static SymCipher Create(SymDefObject symDef = null,
        byte[] keyData = null, byte[] iv = null)
    {
        if (symDef == null)
        {
            symDef = new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb);
        }

        if (symDef.Mode == TpmAlgId.Ofb)
        {
            return null;
        }

        var mode = GetCipherMode(symDef.Mode);
        if (mode == CipherModeNone)
        {
            return null;
        }

        SymmetricAlgorithm alg = null; // = new RijndaelManaged();
//        var limitedSupport = false;
        var feedbackSize = 0;

        switch (symDef.Algorithm) {
            case TpmAlgId.Aes:
                alg = Aes.Create();
                alg.Mode = mode;
                if (mode == CipherMode.CFB)
                {
                    feedbackSize = 8;
                }
                break;
            case TpmAlgId.Tdes:
                // TripleDES is deprecated/weak; treat as unsupported.
                return null;
            default:
                //throw new ArgumentException("Unsupported symmetric algorithm " + symDef.Algorithm);
                return null;
        }

        var blockSize = GetBlockSize(symDef);
        alg.KeySize = symDef.KeyBits;
        alg.BlockSize = blockSize * 8;
        alg.Padding = PaddingMode.None;
        alg.FeedbackSize = feedbackSize == 0 ? alg.BlockSize : feedbackSize;

        if (keyData == null)
        {
            // Generate random key
            alg.IV = Globs.GetZeroBytes(blockSize);
            try
            {
                alg.GenerateKey();
            }
            catch (Exception)
            {
                alg.Dispose();
                throw;
            }
        }
        else
        {
            // Use supplied key bits
            alg.Key = keyData;
            if (iv == null)
            {
                iv = Globs.GetZeroBytes(blockSize);
            }
            else if (iv.Length != blockSize)
            {
                Array.Resize(ref iv, blockSize);
            }
            alg.IV = iv;
        }

        var symCipher = new SymCipher(alg, mode);
//        symCipher.LimitedSupport = limitedSupport;
        return symCipher;
    } // Create()

    const CipherMode CipherModeNone = 0;

    public static CipherMode GetCipherMode(TpmAlgId cipherMode)
    {
        switch (cipherMode)
        {
            case TpmAlgId.Cfb:
                return CipherMode.CFB;
            case TpmAlgId.Ofb:
                return CipherMode.OFB;
            case TpmAlgId.Cbc:
                return CipherMode.CBC;
            case TpmAlgId.Ecb:
                throw new ArgumentException("GetCipherMode: ECB mode is insecure and not supported");
            case TpmAlgId.Ctr:
                // CTR in .NET requires you to manage your own counter.
                return CipherModeNone;
            default:
                throw new ArgumentException("GetCipherMode: Unsupported cipher mode");
        }
    }

    public static byte[] Encrypt(SymDefObject symDef, byte[] key, byte[] iv,
        byte[] dataToEncrypt)
    {
        using (var cipher = Create(symDef, key, iv))
        {
            return cipher.Encrypt(dataToEncrypt);
        }
    }

    public static byte[] Decrypt(SymDefObject symDef, byte[] key, byte[] iv,
        byte[] dataToDecrypt)
    {
        using (var cipher = Create(symDef, key, iv))
        {
            return cipher.Decrypt(dataToDecrypt);
        }
    }

    private static void EncryptCfb(byte[] paddedData, byte[] iv, ICryptoTransform enc)
    {
        for (var i = 0; i < paddedData.Length; i += iv.Length)
        {
            using (var outStream = new MemoryStream())
                using (var s = new CryptoStream(outStream, enc, CryptoStreamMode.Write))
                {
                    s.Write(iv, 0, iv.Length);
                    s.FlushFinalBlock();
                    outStream.ToArray().CopyTo(iv, 0);
                    for (var j = 0; j < iv.Length; ++j)
                        paddedData[i + j] = iv[j] ^= paddedData[i + j];
                }
        }
    }

    /// <summary>
    /// Performs the TPM-defined CFB encrypt using the associated algorithm.
    /// This routine assumes that the integrity value has been prepended.
    /// </summary>
    /// <param name="data"></param>
    /// <param name="iv"></param>
    /// <returns></returns>
    public byte[] Encrypt(byte[] data, byte[] iv = null)
    {
        if (_mode != CipherMode.CBC &&
            _mode != CipherMode.CFB &&
            _mode != CipherMode.OFB)
        {
            throw new ArgumentException("Encrypt: Unsupported symmetric mode");
        }

        var unpadded = data.Length % BlockSize;
        var paddingNeeded = unpadded == 0 ? 0 : BlockSize - unpadded;
        // AddZeroToEnd makes a copy of the data buffer. This is important
        // because the crypto helpers in this file operate in place.
        var paddedData = Globs.AddZeroToEnd(data, paddingNeeded);
        var externalIv = iv != null && iv.Length > 0;
        if (externalIv)
        {
            _alg.IV = iv;
        }

        var enc = _alg.CreateEncryptor();
        if (_mode == CipherMode.CFB)
        {
            EncryptCfb(paddedData, _alg.IV, enc);
        }
        else
        {
            using (var outStream = new MemoryStream())
            {
                var s = new CryptoStream(outStream, enc, CryptoStreamMode.Write);
                s.Write(paddedData, 0, paddedData.Length);
                s.FlushFinalBlock();
                paddedData = outStream.ToArray();
            }
        }

        if (externalIv)
        {
            var src = data;
            var res = paddedData;
            if (res.Length > iv.Length)
            {
                src = Globs.CopyData(data, src.Length - iv.Length, iv.Length);
                res = Globs.CopyData(paddedData, res.Length - iv.Length, iv.Length);
            }

            switch(_mode)
            {
                case CipherMode.CBC:
                case CipherMode.CFB:
                    res.CopyTo(iv, 0);
                    break;
                case CipherMode.OFB:
                    XorEngine.Xor(res, src).CopyTo(iv, 0);
                    break;
                default:
                    throw new ArgumentException("Encrypt: Unsupported symmetric mode");
            }
        }
        return unpadded == 0 ? paddedData : Globs.CopyData(paddedData, 0, data.Length);
    }

    private static void DecryptCfb(byte[] paddedData, byte[] iv, ICryptoTransform enc)
    {
        var tempOut = new byte[iv.Length];
        for (var i = 0; i < paddedData.Length; i += iv.Length)
        {
            using (var outStream = new MemoryStream())
                using (var s = new CryptoStream(outStream, enc, CryptoStreamMode.Write))
                {
                    s.Write(iv, 0, iv.Length);
                    s.FlushFinalBlock();
                    outStream.ToArray().CopyTo(tempOut, 0);
                    for (var j = 0; j < iv.Length; ++j)
                    {
                        iv[j] = paddedData[i + j];
                        paddedData[i + j] = (byte)((tempOut[j] ^ iv[j]) & 0x000000FF);
                    }
                }
        }
    }

    private static bool IsEcbMode(CipherMode mode) => (int)mode == 2;

    public byte[] Decrypt(byte[] data, byte[] iv = null)
    {
        if (IsEcbMode(_mode))
        {
            throw new ArgumentException("Decrypt: ECB mode is insecure and not supported");
        }

        var unpadded = data.Length % BlockSize;
        var paddingNeeded = unpadded == 0 ? 0 : BlockSize - unpadded;
        // AddZeroToEnd makes a copy of the data buffer. This is important
        // because the crypto helpers in this file operate in place.
        var paddedData = Globs.AddZeroToEnd(data, paddingNeeded);
        var externalIv = iv != null && iv.Length > 0;
        if (externalIv)
        {
            _alg.IV = iv;
        }

        byte[] tempOut = null;
        if (_mode == CipherMode.CFB)
        {
            DecryptCfb(paddedData, _alg.IV, _alg.CreateEncryptor());
            tempOut = unpadded == 0 ? paddedData : Globs.CopyData(paddedData, 0, data.Length);
        }
        else
        {
            var dec = _alg.CreateDecryptor();
            tempOut = new byte[data.Length];
            using (var outStream = new MemoryStream(paddedData))
            {
                var s = new CryptoStream(outStream, dec, CryptoStreamMode.Read);
                var numPlaintextBytes = s.Read(tempOut, 0, data.Length);
                Debug.Assert(numPlaintextBytes == data.Length);
            }
        }

        if (externalIv)
        {
            var src = data;
            var res = tempOut;
            if (res.Length > iv.Length)
            {
                src = Globs.CopyData(paddedData, src.Length / iv.Length, iv.Length);
                res = Globs.CopyData(tempOut, res.Length / iv.Length, iv.Length);
            }

            switch(_mode)
            {
                case CipherMode.CBC:
                case CipherMode.CFB:
                    src.CopyTo(iv, 0);
                    break;
                case CipherMode.OFB:
                    XorEngine.Xor(res, src).CopyTo(iv, 0);
                    break;
                case CipherMode.CTS:
                    throw new ArgumentException("Decrypt: Unsupported symmetric mode");
                default:
                    if (IsEcbMode(_mode))
                    {
                        throw new ArgumentException("Decrypt: ECB mode is not supported for security reasons");
                    }
                    throw new ArgumentException("Decrypt: Unsupported symmetric mode");
            }
        }
        return tempOut;
    }

    public void Dispose()
    {
        _alg.Dispose();
    }
}
