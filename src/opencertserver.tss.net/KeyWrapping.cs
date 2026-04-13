/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System.Diagnostics;

namespace OpenCertServer.Tpm2Lib;

/// <summary>
/// This class contains algorithms for wrapping and unwrapping TPM objects
/// </summary>
internal class KeyWrapper
{
    private KeyWrapper()
    {
    }

    /// <summary>
    /// Create an enveloped (encrypted and integrity protected) private area from a provided sensitive.
    /// </summary>
    /// <param name="iv"></param>
    /// <param name="sens"></param>
    /// <param name="nameHash"></param>
    /// <param name="publicName"></param>
    /// <param name="symWrappingAlg"></param>
    /// <param name="symKey"></param>
    /// <param name="parentNameAlg"></param>
    /// <param name="parentSeed"></param>
    /// <param name="f"></param>
    /// <returns></returns>
    public static byte[] CreatePrivateFromSensitive(
        SymDefObject symWrappingAlg,
        byte[] symKey,
        byte[] iv,
        Sensitive sens,
        TpmAlgId nameHash,
        byte[] publicName,
        TpmAlgId parentNameAlg,
        byte[] parentSeed,
        TssObject.Transformer? f = null)
    {
        // ReSharper disable once InconsistentNaming
        var tpm2bIv = Marshaller.ToTpm2B(iv);
        Transform(tpm2bIv, f);

        var sensitive = sens.GetTpmRepresentation();
        Transform(sensitive, f);

        // ReSharper disable once InconsistentNaming
        var tpm2bSensitive = Marshaller.ToTpm2B(sensitive);
        Transform(tpm2bSensitive, f);

        var encSensitive = SymCipher.Encrypt(symWrappingAlg, symKey, iv, tpm2bSensitive);
        Transform(encSensitive, f);
        var decSensitive = SymCipher.Decrypt(symWrappingAlg, symKey, iv, encSensitive);
        Debug.Assert(f != null || Globs.ArraysAreEqual(decSensitive, tpm2bSensitive));

        var hmacKeyBits = CryptoLib.DigestSize(parentNameAlg) * 8;
        var hmacKey = KDF.KDFa(parentNameAlg, parentSeed, "INTEGRITY", [], [], hmacKeyBits);
        Transform(hmacKey, f);

        var dataToHmac = Marshaller.GetTpmRepresentation(tpm2bIv,
            encSensitive,
            publicName);
        Transform(dataToHmac, f);

        var outerHmac = CryptoLib.Hmac(parentNameAlg, hmacKey, dataToHmac);
        Transform(outerHmac, f);

        var priv = Marshaller.GetTpmRepresentation(Marshaller.ToTpm2B(outerHmac),
            tpm2bIv,
            encSensitive);
        Transform(priv, f);
        return priv;
    }

    private static void Transform(byte[] x, TssObject.Transformer? f)
    {
        f?.Invoke(x);
    }
}
