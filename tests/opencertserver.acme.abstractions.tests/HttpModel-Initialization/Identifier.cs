namespace OpenCertServer.Acme.Abstractions.Tests.HttpModel_Initialization
{
    using Xunit;

    public sealed class Identifier
    {
        [Fact]
        public void Ctor_Intializes_All_Properties()
        {
            var identifier = new Model.Identifier("dns", "www.example.com");
            var sut = new HttpModel.Identifier(identifier);

            Assert.Equal(identifier.Type, sut.Type);
            Assert.Equal(identifier.Value, sut.Value);
        }
    }
}
