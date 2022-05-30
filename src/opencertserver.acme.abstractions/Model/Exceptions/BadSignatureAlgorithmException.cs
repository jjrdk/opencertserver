namespace OpenCertServer.Acme.Abstractions.Model.Exceptions
{
    public class BadSignatureAlgorithmException : AcmeException
    {
        private const string Detail = "The ALG is not supported.";

        public BadSignatureAlgorithmException() : base(Detail) { }

        public override string ErrorType
        {
            get { return "badSignatureAlgorithm"; }
        }
    }
}
