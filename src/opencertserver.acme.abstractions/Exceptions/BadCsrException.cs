namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when an ACME finalization request contains a malformed or unacceptable CSR.
/// </summary>
public sealed class BadCsrException : AcmeException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="BadCsrException"/> class.
    /// </summary>
    /// <param name="message">The human-readable detail for the CSR failure.</param>
    public BadCsrException(string message)
        : base(message)
    {
    }

    /// <inheritdoc />
    public override string ErrorType
    {
        get { return "badCSR"; }
    }
}
