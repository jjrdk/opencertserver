﻿namespace OpenCertServer.Acme.AspNetClient.Exceptions
{
    using System;
    using System.Runtime.Serialization;

    internal class OrderInvalidException : Exception
	{
		public OrderInvalidException()
		{
		}

		public OrderInvalidException(string message) : base(message)
		{
		}

		public OrderInvalidException(string message, Exception innerException) : base(message, innerException)
		{
		}

		protected OrderInvalidException(SerializationInfo info, StreamingContext context) : base(info, context)
		{
		}
	}
}
