﻿namespace OpenCertServer.Acme.Abstractions.Model
{
    using Microsoft.IdentityModel.Tokens;

    public class CryptoString
    {
        private CryptoString(int byteCount)
        {
            var bytes = new byte[byteCount];

            using (var cryptoRng = System.Security.Cryptography.RandomNumberGenerator.Create())
                cryptoRng.GetBytes(bytes);

            Value = Base64UrlEncoder.Encode(bytes);
        }

        private string Value { get; }
        public static string NewValue(int byteCount = 48) => new CryptoString(byteCount).Value;
    }
}
