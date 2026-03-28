namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when an ACME request could not be authorized.
/// </summary>
public sealed class NotAuthorizedException : MalformedRequestException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NotAuthorizedException"/> class with a standard error message.
    /// </summary>
    public NotAuthorizedException()
        :base("The request could not be authorized.")
    { }
}