namespace OpenCertServer.Acme.Abstractions.HttpModel;

using System.Globalization;

/// <summary>
/// Represents an ACME challenge
/// https://tools.ietf.org/html/rfc8555#section-7.1.5
/// </summary>
public sealed class Challenge
{
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


    public string Type { get; }
    public string Token { get; }

    public string Status { get; }

    public string? Validated { get; }
    public AcmeError? Error { get; }

    public string Url { get; }
}
