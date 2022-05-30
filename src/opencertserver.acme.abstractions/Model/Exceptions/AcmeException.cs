﻿namespace OpenCertServer.Acme.Abstractions.Model.Exceptions
{
    using System;

    public abstract class AcmeException : Exception
    {
        protected AcmeException(string message)
            : base(message) { }

        public string UrnBase { get; protected set; } = "urn:ietf:params:acme:error";
        public abstract string ErrorType { get; }

        public virtual HttpModel.AcmeError GetHttpError()
        {
            return new HttpModel.AcmeError($"{UrnBase}:{ErrorType}", Message);
        }
    }
}
