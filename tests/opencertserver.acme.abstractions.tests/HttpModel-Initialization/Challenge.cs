namespace OpenCertServer.Acme.Abstractions.Tests.HttpModel_Initialization
{
    using System;
    using System.Collections.Generic;
    using Xunit;

    public sealed class Challenge
    {
        private (Model.Challenge challenge, string challengeUrl) CreateTestModel()
        {
            var account = new Model.Account(new Model.Jwk(StaticTestData.JwkJson), new List<string> { "some@example.com" }, null);
            var order = new Model.Order(account, new List<Model.Identifier> { new Model.Identifier("dns", "www.example.com") });
            var authorization = new Model.Authorization(order, order.Identifiers.First(), DateTimeOffset.UtcNow);
            var challenge = new Model.Challenge(authorization, "http-01");

            return (challenge, "https://challenge.example.com");
        }

        [Fact]
        public void Ctor_Intializes_All_Properties()
        {
            var (challenge, challengeUrl) = CreateTestModel();
            var sut = new HttpModel.Challenge(challenge, challengeUrl);

            Assert.Equal(challenge.Status.ToString().ToLowerInvariant(), sut.Status);
            Assert.Equal(challenge.Token, sut.Token);
            Assert.Equal(challenge.Type, sut.Type);
            Assert.Equal(challengeUrl, sut.Url);

            Assert.Null(sut.Error);
            Assert.Null(sut.Validated);
        }

        [Fact]
        public void Ctor_Initializes_Validated()
        {
            var (challenge, challengeUrl) = CreateTestModel();
            challenge.Validated = DateTimeOffset.UtcNow;
            
            var sut = new HttpModel.Challenge(challenge, challengeUrl);

            Assert.Equal(challenge.Validated.Value.ToString("o"), sut.Validated);
        }

        [Fact]
        public void Ctor_Initializes_Error()
        {
            var (challenge, challengeUrl) = CreateTestModel();
            challenge.Error = new Model.AcmeError("type", "detail");

            var sut = new HttpModel.Challenge(challenge, challengeUrl);

            Assert.NotNull(sut.Error);
        }
    }
}
