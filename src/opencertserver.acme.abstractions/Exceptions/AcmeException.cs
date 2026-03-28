namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Represents the abstract base exception for ACME protocol errors exposed by the server.
/// </summary>
public abstract class AcmeException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AcmeException"/> class with the specified error message.
    /// </summary>
    /// <param name="message">The message that describes the ACME error condition.</param>
    protected AcmeException(string message)
        : base(message) { }

    /// <summary>
    /// Gets the base URN used when composing the ACME error type returned to clients.
    /// </summary>
    public string UrnBase { get; protected set; } = "urn:ietf:params:acme:error";

    /// <summary>
    /// Gets the ACME error type suffix appended to <see cref="UrnBase"/> for the HTTP error response.
    /// </summary>
    public abstract string ErrorType { get; }
}
