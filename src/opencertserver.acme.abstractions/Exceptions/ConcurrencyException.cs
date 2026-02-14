namespace OpenCertServer.Acme.Abstractions.Exceptions;

public sealed class ConcurrencyException : InvalidOperationException
{
    public ConcurrencyException()
        : base($"Object has been changed since loading")
    { }
}