using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Acme.Abstractions.Tests.Model_Initialization;

using System;
using System.Collections.Generic;
using Model;
using Xunit;

public sealed class Account
{
    [Fact]
    public void Ctor_Populates_All_Properties()
    {
        var jwk = new JsonWebKey(StaticTestData.JwkJson);
        var contacts = new List<string> { "some@example.com" };
        var tosAccepted = DateTimeOffset.UtcNow;

        var sut = new Model.Account(jwk, contacts, tosAccepted);

        Assert.Equal(jwk, sut.Jwk);
        Assert.Equal(contacts, sut.Contacts);
        Assert.Equal(tosAccepted, sut.TosAccepted);

        Assert.True(sut.AccountId.Length > 0);
        Assert.Equal(AccountStatus.Valid, sut.Status);
    }
}

public sealed class Authorization
{

}

public sealed class Challenge
{

}

public sealed class Order
{

}
