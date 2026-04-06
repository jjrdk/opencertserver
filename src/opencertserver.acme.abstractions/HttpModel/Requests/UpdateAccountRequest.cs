using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

using System.Collections.Generic;

/// <summary>
/// Represents a request to retrieve, update, or deactivate an ACME account.
/// </summary>
public sealed class UpdateAccountRequest
{
    /// <summary>
    /// Gets or sets the updated contact URIs for the account.
    /// </summary>
    public List<string>? Contact { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the terms of service have been agreed to.
    /// </summary>
    public bool? TermsOfServiceAgreed { get; set; }

    /// <summary>
    /// Gets or sets the requested account status.
    /// </summary>
    public AccountStatus? Status { get; set; }
}

