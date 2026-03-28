namespace OpenCertServer.Acme.Abstractions.HttpModel;

using System.Collections.Generic;
using System.Globalization;

/// <summary>
/// Represents an ACME authorization object.
/// See RFC 8555, section 7.1.4.
/// </summary>
public sealed class Authorization
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Authorization"/> class from a model and challenge list.
    /// </summary>
    /// <param name="model">The authorization model.</param>
    /// <param name="challenges">The list of challenges for this authorization.</param>
    public Authorization(Model.Authorization model, IEnumerable<Challenge> challenges)
    {
        if (model is null)
        {
            throw new ArgumentNullException(nameof(model));
        }

        if (challenges is null)
        {
            throw new ArgumentNullException(nameof(challenges));
        }

        Status = model.Status.ToString().ToLowerInvariant();

        Expires = model.Expires.ToString("o", CultureInfo.InvariantCulture);
        Wildcard = model.IsWildcard;

        Identifier = new Identifier(model.Identifier);
        Challenges = new List<Challenge>(challenges);
    }

    /// <summary>
    /// Gets the authorization status (e.g., pending, valid, invalid).
    /// </summary>
    public string Status { get; }

    /// <summary>
    /// Gets the identifier for which authorization is being requested.
    /// </summary>
    public Identifier Identifier { get; }

    /// <summary>
    /// Gets the expiration date/time of the authorization, if set.
    /// </summary>
    public string? Expires { get; }

    /// <summary>
    /// Gets a value indicating whether the identifier is a wildcard.
    /// </summary>
    public bool? Wildcard { get; }

    /// <summary>
    /// Gets the list of challenges associated with this authorization.
    /// </summary>
    public IEnumerable<Challenge> Challenges { get; }
}
