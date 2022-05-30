namespace OpenCertServer.Acme.Abstractions.Model.Exceptions
{
    using System;

    public class ConcurrencyException : InvalidOperationException
    {
        public ConcurrencyException()
            : base($"Object has been changed since loading")
        { }
    }
}
