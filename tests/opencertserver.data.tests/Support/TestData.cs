using System.Security.Cryptography;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;

namespace opencertserver.data.tests.Support;

using Account = OpenCertServer.Acme.Abstractions.Model.Account;
using Order = OpenCertServer.Acme.Abstractions.Model.Order;
using Authorization = OpenCertServer.Acme.Abstractions.Model.Authorization;
using Challenge = OpenCertServer.Acme.Abstractions.Model.Challenge;

internal static class TestData
{
    public static Account NewAccount()
    {
        using var rsa = RSA.Create(2048);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa.ExportParameters(false)));
        return new Account(jwk, ["mailto:tester@example.com"], DateTimeOffset.UtcNow, "external-id")
        {
            AccountUri = "https://ca.example/acme/account"
        };
    }

    public static Order NewOrder(Account account)
    {
        var identifier = new Identifier { Type = IdentifierType.Dns, Value = "valid.example" };
        var order = new Order(account, [identifier], "rsa")
        {
            Expires = DateTimeOffset.UtcNow.AddHours(2),
            NotBefore = DateTimeOffset.UtcNow,
            NotAfter = DateTimeOffset.UtcNow.AddDays(1)
        };
        var auth = new Authorization(order, identifier, DateTimeOffset.UtcNow.AddHours(2));
        _ = new Challenge(auth, "http-01");
        return order;
    }
}
