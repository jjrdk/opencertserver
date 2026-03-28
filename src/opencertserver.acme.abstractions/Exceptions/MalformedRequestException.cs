namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when an ACME request is malformed or contains invalid data.
/// </summary>
public class MalformedRequestException : AcmeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="MalformedRequestException"/> class with a custom error message.
    /// </summary>
    /// <param name="message">The message that describes the malformed request error.</param>
    public MalformedRequestException(string message)
        : base(message)
    { }

    /// <summary>
    /// Gets the ACME error type string for a malformed request error.
    /// </summary>
    public override string ErrorType
    {
        get { return "malformed"; }
    }
}
