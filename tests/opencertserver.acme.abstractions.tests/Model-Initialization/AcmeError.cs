namespace OpenCertServer.Acme.Abstractions.Tests.Model_Initialization;

using Xunit;

public sealed class AcmeError
{
    [Fact]
    public void Ctor_Populates_All_Properties()
    {
        var type = "custom:error";
        var detail = "detail";
        var identifier = new Model.Identifier("dns", "www.example.com");

        var sut = new Model.AcmeError(type, detail, identifier);

        Assert.Equal(type, sut.Type);
        Assert.Equal(detail, sut.Detail);
        Assert.Equal(identifier, sut.Identifier);
    }

    [Fact]
    public void Ctor_Adds_IETF_Error_Urn()
    {
        var type = "test";
        var detail = "detail";

        var sut = new Model.AcmeError(type, detail);

        Assert.Equal("urn:ietf:params:acme:error:test", sut.Type);
    }
}