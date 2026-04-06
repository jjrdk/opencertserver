namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

using System.Collections.Generic;

/// <summary>
/// Represents a request to create or get an ACME account.
/// </summary>
public sealed class CreateOrGetAccount
{
    /// <summary>
    /// Gets or sets the contact URIs for the account.
    /// </summary>
    public List<string>? Contact { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the terms of service have been agreed to.
    /// </summary>
    public bool? TermsOfServiceAgreed { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether to only return an existing account.
    /// </summary>
    public bool OnlyReturnExisting { get; set; }
}
