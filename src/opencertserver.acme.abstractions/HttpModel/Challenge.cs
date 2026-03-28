namespace OpenCertServer.Acme.Abstractions.HttpModel;

using System.Globalization;

/// <summary>
/// Represents an ACME challenge.
/// See RFC 8555, section 7.1.5.
/// </summary>
public sealed class Challenge
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Challenge"/> class from a model and challenge URL.
    /// </summary>
    /// <param name="model">The challenge model.</param>
    /// <param name="challengeUrl">The URL for this challenge resource.</param>
    public Challenge(Model.Challenge model, string challengeUrl)
    {
        ArgumentNullException.ThrowIfNull(model);
        ArgumentException.ThrowIfNullOrEmpty(challengeUrl);

        Type = model.Type;
        Token = model.Token;

        Status = model.Status.ToString().ToLowerInvariant();
        Url = challengeUrl;

        Validated = model.Validated?.ToString("o", CultureInfo.InvariantCulture);
        Error = model.Error != null ? new AcmeError(model.Error) : null;
    }

    /// <summary>
    /// Gets the challenge type (e.g., http-01, dns-01).
    /// </summary>
    public string Type { get; }

    /// <summary>
    /// Gets the challenge token value.
    /// </summary>
    public string Token { get; }

    /// <summary>
    /// Gets the challenge status (e.g., pending, valid, invalid).
    /// </summary>
    public string Status { get; }

    /// <summary>
    /// Gets the date/time when the challenge was validated, if set.
    /// </summary>
    public string? Validated { get; }

    /// <summary>
    /// Gets the error object associated with the challenge, if any.
    /// </summary>
    public AcmeError? Error { get; }

    /// <summary>
    /// Gets the URL for this challenge resource.
    /// </summary>
    public string Url { get; }
}
