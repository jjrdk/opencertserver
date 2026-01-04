using System;
using System.IO;
using System.Text.Json;
using CertesSlim.Acme.Resource;
using CertesSlim.Json;
using Xunit;

namespace Certes.Acme.Resource;

public class AccountTests
{
    [Fact]
    public void CanGetSetProperties()
    {
        var account = new Account();
        account.VerifyGetterSetter(a => a.Status, AccountStatus.Valid);
        account.VerifyGetterSetter(a => a.Contact, ["mailto:hello@example.com"]);
        account.VerifyGetterSetter(a => a.Orders, new Uri("http://certes.is.working"));
        account.VerifyGetterSetter(a => a.TermsOfServiceAgreed, true);

        var r = new Account.Payload();
        r.VerifyGetterSetter(a => a.OnlyReturnExisting, true);
    }

    [Fact]
    public void CanBeSerialized()
    {
        var srcJson = File.ReadAllText("./Data/account.json");
        var deserialized = JsonSerializer.Deserialize(srcJson, CertesSerializerContext.Default.Account);

        Assert.Equal(AccountStatus.Valid, deserialized.Status);
        Assert.Equal(2, deserialized.Contact?.Count);
    }
}