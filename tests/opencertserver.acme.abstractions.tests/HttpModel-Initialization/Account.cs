namespace OpenCertServer.Acme.Abstractions.Tests.HttpModel_Initialization
{
    using System;
    using System.Collections.Generic;
    using Model;
    using Xunit;

    public class Account
    {
        [Fact]
        public void Ctor_Initializes_All_Properties()
        {
            var account = new Model.Account(new Jwk(StaticTestData.JwkJson), new List<string> { "some@example.com", "other@example.com" }, DateTimeOffset.UtcNow);
            var ordersUrl = "https://orders.example.org/";

            var sut = new HttpModel.Account(account, ordersUrl);

            Assert.Equal(account.Contacts, sut.Contact);
            Assert.Equal(ordersUrl, sut.Orders);
            Assert.Equal("valid", sut.Status);
            Assert.True(sut.TermsOfServiceAgreed);
        }

        [Fact]
        public void Empty_TOSAccepted_Will_Yield_False()
        {
            var account = new Model.Account(new Model.Jwk(StaticTestData.JwkJson), new List<string> { "some@example.com", "other@example.com" }, null);
            var ordersUrl = "https://orders.example.org/";

            var sut = new HttpModel.Account(account, ordersUrl);

            Assert.False(sut.TermsOfServiceAgreed);
        }
    }
}
