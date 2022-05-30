namespace OpenCertServer.Acme.Abstractions.Tests.Model_Initialization
{
    using Xunit;

    public class CryptoString
    {
        [Fact]
        public void CryptoString_Seems_Filled()
        {
            var sut = Model.CryptoString.NewValue(48);

            Assert.False(string.IsNullOrWhiteSpace(sut));
            Assert.Equal(64, sut.Length);
        }
    }
}
