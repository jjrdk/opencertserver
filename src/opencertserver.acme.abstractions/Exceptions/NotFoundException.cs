namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when the requested ACME resource could not be found.
/// </summary>
public sealed class NotFoundException : MalformedRequestException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NotFoundException"/> class with a standard error message.
    /// </summary>
    public NotFoundException()
        :base("The requested resource could not be found.")
    { }
}