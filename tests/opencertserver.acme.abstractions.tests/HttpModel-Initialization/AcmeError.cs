namespace OpenCertServer.Acme.Abstractions.Tests.HttpModel_Initialization
{
    using System.Collections.Generic;
    using Xunit;

    public class AcmeError
    {
        [Fact]
        public void Ctor_Initializes_Type_And_Detail()
        {
            var acmeError = new Model.AcmeError("type", "detail");
            var sut = new HttpModel.AcmeError(acmeError);

            Assert.Equal(acmeError.Type, sut.Type);
            Assert.Equal(acmeError.Detail, sut.Detail);
            Assert.Null(sut.Identifier);
            Assert.Null(sut.Subproblems);
        }

        [Fact]
        public void Ctor_Intializes_All_Properties()
        {
            var acmeError = new Model.AcmeError("type", "detail", new Model.Identifier("dns", "www.example.com"), new List<Model.AcmeError> { new Model.AcmeError("innerType", "innerDetail") });
            var sut = new HttpModel.AcmeError(acmeError);

            Assert.Equal(acmeError.Type, sut.Type);
            Assert.Equal(acmeError.Detail, sut.Detail);
            
            Assert.NotNull(sut.Identifier);

            Assert.NotNull(sut.Subproblems);
            Assert.Single(sut.Subproblems);
        }
    }
}
