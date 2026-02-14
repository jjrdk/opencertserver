namespace OpenCertServer.Acme.Abstractions.HttpModel;

using System.Collections.Generic;

/// <summary>
/// Represents the data of an ACME account
/// https://tools.ietf.org/html/rfc8555#section-7.1.2
/// </summary>
public sealed class Account
{
    public Account(Model.Account model, string ordersUrl)
    {
        ArgumentNullException.ThrowIfNull(model);

        Status = model.Status.ToString().ToLowerInvariant();

        Contact = model.Contacts;
        TermsOfServiceAgreed = model.TosAccepted.HasValue;

        ExternalAccountBinding = null;
        Orders = ordersUrl;
    }

    public string Status { get; set; }
    public string? Orders { get; set; }

    public List<string>? Contact { get; set; }
    public bool? TermsOfServiceAgreed { get; set; }

    public object? ExternalAccountBinding { get; set; }
}
