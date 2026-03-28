namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when access to the requested ACME resource is not allowed.
/// </summary>
public sealed class NotAllowedException : MalformedRequestException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NotAllowedException"/> class with a standard error message.
    /// </summary>
    public NotAllowedException()
        : base("The requested resoruce may not be accessed.")
    { }
}