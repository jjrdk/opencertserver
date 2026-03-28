namespace OpenCertServer.Acme.Abstractions.HttpModel;

using System.Collections.Generic;

/// <summary>
/// Represents the data of an ACME account.
/// See RFC 8555, section 7.1.2.
/// </summary>
public sealed class Account
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Account"/> class from a model and orders URL.
    /// </summary>
    /// <param name="model">The account model.</param>
    /// <param name="ordersUrl">The URL for the account's orders list.</param>
    public Account(Model.Account model, string ordersUrl)
    {
        ArgumentNullException.ThrowIfNull(model);

        Status = model.Status.ToString().ToLowerInvariant();

        Contact = model.Contacts;
        TermsOfServiceAgreed = model.TosAccepted.HasValue;

        ExternalAccountBinding = null;
        Orders = ordersUrl;
    }

    /// <summary>
    /// Gets or sets the account status (e.g., valid, deactivated, revoked).
    /// </summary>
    public string Status { get; set; }

    /// <summary>
    /// Gets or sets the URL for the list of orders associated with the account.
    /// </summary>
    public string? Orders { get; set; }

    /// <summary>
    /// Gets or sets the contact URIs for the account.
    /// </summary>
    public List<string>? Contact { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the terms of service have been agreed to.
    /// </summary>
    public bool? TermsOfServiceAgreed { get; set; }

    /// <summary>
    /// Gets or sets the external account binding object, if present.
    /// </summary>
    public object? ExternalAccountBinding { get; set; }
}
