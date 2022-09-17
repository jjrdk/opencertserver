namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests
{
    using System;
    using System.Collections.Generic;

    public sealed class CreateOrderRequest
    {
        public List<Identifier>? Identifiers { get; set; }

        public DateTimeOffset? NotBefore { get; set; }
        public DateTimeOffset? NotAfter { get; set; }
    }
}
