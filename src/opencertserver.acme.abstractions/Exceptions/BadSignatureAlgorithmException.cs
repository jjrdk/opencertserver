
namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when an unsupported or invalid signature algorithm is used in an ACME request.
/// </summary>
public sealed class BadSignatureAlgorithmException : AcmeException
{
    private const string Detail = "The ALG is not supported.";

    /// <summary>
    /// Initializes a new instance of the <see cref="BadSignatureAlgorithmException"/> class with a standard error message.
    /// </summary>
    public BadSignatureAlgorithmException() : base(Detail) { }

    /// <summary>
    /// Gets the ACME error type string for a bad signature algorithm error.
    /// </summary>
    public override string ErrorType
    {
        get { return "badSignatureAlgorithm"; }
    }
}
