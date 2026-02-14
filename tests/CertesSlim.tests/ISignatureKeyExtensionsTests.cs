using System.Security.Cryptography;
using System.Text;
using CertesSlim.Json;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace CertesSlim.Tests;

public class ISignatureKeyExtensionsTests
{
    [Fact]
    public void CanGenerateDnsRecordValue()
    {
        var key = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        using (var sha256 = SHA256.Create())
        {
            Assert.Equal(
                sha256.ComputeHash(Encoding.UTF8.GetBytes(key.KeyAuthorization("token"))).ToBase64String(),
                key.DnsTxt("token"));
        }
    }
}