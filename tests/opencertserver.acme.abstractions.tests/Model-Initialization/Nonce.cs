namespace OpenCertServer.Acme.Abstractions.Tests.Model_Initialization;

using Xunit;

public sealed class Nonce
{
    [Fact]
    public void Ctor_Populates_All_Properties()
    {
        var token = "ABC";
        var sut = new Model.Nonce(token);

        Assert.Equal(token, sut.Token);
    }
}