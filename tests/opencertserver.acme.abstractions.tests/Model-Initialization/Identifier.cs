namespace OpenCertServer.Acme.Abstractions.Tests.Model_Initialization
{
    using Xunit;

    public sealed class Identifier
    {
        [Fact]
        public void Ctor_Populates_All_Properties()
        {
            var type = "dns";
            var value = "www.example.com";

            var sut = new Model.Identifier(type, value);

            Assert.Equal(type, sut.Type);
            Assert.Equal(value, sut.Value);
            Assert.False(sut.IsWildcard);
        }

        [Fact]
        public void Ctor_Normalizes_All_Properties()
        {
            var type = " DNS ";
            var value = " www.EXAMPLE.com ";

            var sut = new Model.Identifier(type, value);

            Assert.Equal("dns", sut.Type);
            Assert.Equal("www.example.com", sut.Value);
        }

        [Fact]
        public void Ctor_Sets_Wildcard() 
        {
            var sut = new Model.Identifier("dns", "*.example.com");

            Assert.True(sut.IsWildcard);
        }
    }
}
