namespace OpenCertServer.Acme.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when an object has been modified concurrently since it was loaded, indicating a concurrency conflict.
/// </summary>
public sealed class ConcurrencyException : InvalidOperationException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ConcurrencyException"/> class with a standard concurrency conflict message.
    /// </summary>
    public ConcurrencyException()
        : base("Object has been changed since loading")
    { }
}
