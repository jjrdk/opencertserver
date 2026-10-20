namespace CertesSlim.Tests;

using System.Security.Cryptography;
using System.Text;
using CertesSlim.Json;
using Microsoft.IdentityModel.Tokens;
using Xunit;

public class ISignatureKeyExtensionsTests
{
    [Fact]
    public void CanGenerateDnsRecordValue()
    {
        var key = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
        Assert.Equal(
            SHA256.HashData(Encoding.UTF8.GetBytes(key.KeyAuthorization("token"))).ToBase64String(),
            key.DnsTxt("token"));
    }
}
