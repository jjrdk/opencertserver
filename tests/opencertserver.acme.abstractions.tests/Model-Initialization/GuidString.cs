namespace OpenCertServer.Acme.Abstractions.Tests.Model_Initialization;

using Xunit;

public sealed class GuidString
{
    [Fact]
    public void GuidString_Seems_Filled()
    {
        var sut = Model.GuidString.NewValue();

        Assert.False(string.IsNullOrWhiteSpace(sut));
        Assert.Equal(22, sut.Length);
    }
}