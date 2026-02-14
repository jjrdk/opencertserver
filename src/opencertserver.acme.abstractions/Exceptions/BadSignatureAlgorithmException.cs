namespace OpenCertServer.Acme.Abstractions.Exceptions;

public sealed class BadSignatureAlgorithmException : AcmeException
{
    private const string Detail = "The ALG is not supported.";

    public BadSignatureAlgorithmException() : base(Detail) { }

    public override string ErrorType
    {
        get { return "badSignatureAlgorithm"; }
    }
}