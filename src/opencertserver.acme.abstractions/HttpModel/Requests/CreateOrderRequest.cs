namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

using System;
using System.Collections.Generic;

/// <summary>
/// Represents a request to create a new ACME order.
/// </summary>
public sealed class CreateOrderRequest
{
    /// <summary>
    /// Gets or sets the list of identifiers for the order.
    /// </summary>
    public List<Identifier>? Identifiers { get; set; }
    /// <summary>
    /// Gets or sets the requested certificate profile, if any.
    /// </summary>
    public string? Profile { get; set; }
    /// <summary>
    /// Gets or sets the not-before date/time for the requested certificate, if any.
    /// </summary>
    public DateTimeOffset? NotBefore { get; set; }
    /// <summary>
    /// Gets or sets the not-after date/time for the requested certificate, if any.
    /// </summary>
    public DateTimeOffset? NotAfter { get; set; }
}
