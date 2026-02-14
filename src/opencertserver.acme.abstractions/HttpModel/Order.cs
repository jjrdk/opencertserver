using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Abstractions.HttpModel;

using System.Collections.Generic;
using System.Globalization;
using System.Linq;

/// <summary>
/// Represents an ACME order
/// https://tools.ietf.org/html/rfc8555#section-7.1.3
/// </summary>
public sealed class Order
{
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

        switch (model.Status)
        {
            case OrderStatus.Ready:
                Finalize = finalizeUrl;
                break;
            case OrderStatus.Valid:
                Certificate = certificateUrl;
                break;
        }

        if (model.Error != null)
        {
            Error = new AcmeError(model.Error);
        }
    }

    public string Status { get; }

    public List<Identifier> Identifiers { get; }

    public string? Expires { get; }
    public string? NotBefore { get; }
    public string? NotAfter { get; }

    public AcmeError? Error { get; }

    public List<Uri> Authorizations { get; }

    public Uri? Finalize { get; }
    public Uri? Certificate { get; }
}
