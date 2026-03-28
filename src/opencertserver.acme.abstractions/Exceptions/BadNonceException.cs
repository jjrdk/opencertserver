
namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when an ACME request contains an invalid or unacceptable nonce value.
/// </summary>
public sealed class BadNonceException : AcmeException
{
    private const string Detail = "The nonce could not be accepted.";

    /// <summary>
    /// Initializes a new instance of the <see cref="BadNonceException"/> class with a standard error message.
    /// </summary>
    public BadNonceException() : base(Detail) { }

    /// <summary>
    /// Gets the ACME error type string for a bad nonce error.
    /// </summary>
    public override string ErrorType
    {
        get { return "badNonce"; }
    }
}
