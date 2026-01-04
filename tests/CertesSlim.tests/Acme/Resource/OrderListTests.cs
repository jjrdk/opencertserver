using System;
using CertesSlim.Acme.Resource;
using Xunit;

namespace CertesSlim.Tests.Acme.Resource;

public class OrderListTests
{
    [Fact]
    public void CanGetSetProperties()
    {
        var entity = new OrderList();
        entity.VerifyGetterSetter(a => a.Orders, [new Uri("http://certes.is.working")]);
    }
}