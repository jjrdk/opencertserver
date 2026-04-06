using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Abstractions.HttpModel;

using System.Collections.Generic;
using System.Globalization;
using System.Linq;

/// <summary>
/// Represents an ACME order.
/// See RFC 8555, section 7.1.3.
/// </summary>
public sealed class Order
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Order"/> class from a model and related URLs.
    /// </summary>
    /// <param name="model">The order model.</param>
    /// <param name="authorizationUrls">The list of authorization URLs for this order.</param>
    /// <param name="finalizeUrl">The finalize URL for this order, if any.</param>
    /// <param name="certificateUrl">The certificate URL for this order, if any.</param>
    public Order(
        Model.Order model,
        IEnumerable<Uri> authorizationUrls,
        Uri? finalizeUrl,
        Uri? certificateUrl)
    {
        ArgumentNullException.ThrowIfNull(model);
        ArgumentNullException.ThrowIfNull(authorizationUrls);

        Status = model.Status.ToString().ToLowerInvariant();

        Expires = model.Expires?.ToString("o", CultureInfo.InvariantCulture);
        NotBefore = model.NotBefore?.ToString("o", CultureInfo.InvariantCulture);
        NotAfter = model.NotAfter?.ToString("o", CultureInfo.InvariantCulture);

        Identifiers = model.Identifiers.Select(x => new Identifier(x)).ToList();

        Authorizations = [..authorizationUrls];

        Finalize = finalizeUrl;

        if (model.Status == OrderStatus.Valid)
        {
            Certificate = certificateUrl;
        }

        if (model.Error != null)
        {
            Error = new AcmeError(model.Error);
        }
    }

    /// <summary>
    /// Gets the order status (e.g., pending, ready, valid, invalid).
    /// </summary>
    public string Status { get; }

    /// <summary>
    /// Gets the list of identifiers for the order.
    /// </summary>
    public List<Identifier> Identifiers { get; }

    /// <summary>
    /// Gets the expiration date/time of the order, if set.
    /// </summary>
    public string? Expires { get; }
    /// <summary>
    /// Gets the not-before date/time for the order, if set.
    /// </summary>
    public string? NotBefore { get; }
    /// <summary>
    /// Gets the not-after date/time for the order, if set.
    /// </summary>
    public string? NotAfter { get; }

    /// <summary>
    /// Gets the error object associated with the order, if any.
    /// </summary>
    public AcmeError? Error { get; }

    /// <summary>
    /// Gets the list of authorization URLs for the order.
    /// </summary>
    public List<Uri> Authorizations { get; }

    /// <summary>
    /// Gets the finalize URL for the order, if any.
    /// </summary>
    public Uri? Finalize { get; }
    /// <summary>
    /// Gets the certificate URL for the order, if any.
    /// </summary>
    public Uri? Certificate { get; }
}
