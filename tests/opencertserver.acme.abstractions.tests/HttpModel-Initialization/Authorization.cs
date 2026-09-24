using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Abstractions.Tests.HttpModel_Initialization;

using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using Xunit;

public sealed class Authorization
{
    private (Model.Authorization authorization, List<HttpModel.Challenge> challenges) CreateTestModel()
    {
        var account = new Model.Account(new JsonWebKey(StaticTestData.JwkJson), new List<string> { "some@example.com" },
            null);
        var order = new Model.Order(account,
            new List<Identifier> { new() { Type = IdentifierType.Dns, Value = "*.example.com" } }, null);
        var authorization = new Model.Authorization(order, order.Identifiers.First(), DateTimeOffset.UtcNow);
        var challenge = new Model.Challenge(authorization, "http-01");

        return (authorization, [new HttpModel.Challenge(challenge, "https://challenge.example.com/")]);
    }

    [Fact]
    public void Ctor_Intializes_All_Properties()
    {
        var (authorization, challenges) = CreateTestModel();
        var sut = new HttpModel.Authorization(authorization, challenges);

        Assert.NotNull(sut.Challenges);
        Assert.Single(sut.Challenges);

        Assert.Equal(authorization.Expires.ToString("o"), sut.Expires);
        Assert.Equal("*.example.com", sut.Identifier.Value);
        Assert.Equal("pending", sut.Status);
        Assert.True(sut.Wildcard);
    }
}
