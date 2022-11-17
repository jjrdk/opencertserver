namespace OpenCertServer.Acme.AspNetClient.Exceptions;

using System;

internal sealed class OrderInvalidException : Exception
{
    public OrderInvalidException(string message, Exception innerException) : base(message, innerException)
    {
    }
}