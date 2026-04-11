namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when an ACME external account binding (RFC 8555 §7.3.4) fails validation.
/// Maps to the "externalAccountRequired" ACME error type.
/// </summary>
public class ExternalAccountBindingException : AcmeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ExternalAccountBindingException"/> class
    /// with the supplied error detail message.
    /// </summary>
    /// <param name="message">A human-readable description of why the EAB validation failed.</param>
    public ExternalAccountBindingException(string message)
        : base(message)
    { }

    /// <inheritdoc />
    public override string ErrorType
    {
        get { return "externalAccountRequired"; }
    }
}

