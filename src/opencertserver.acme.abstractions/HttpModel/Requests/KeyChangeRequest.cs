using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

/// <summary>
/// Represents the inner payload for an ACME account key rollover request.
/// </summary>
public sealed class KeyChangeRequest
{
    /// <summary>
    /// Gets or sets the account URL being updated.
    /// </summary>
    public Uri? Account { get; set; }

    /// <summary>
    /// Gets or sets the account's current (old) key.
    /// </summary>
    public JsonWebKey? OldKey { get; set; }
}

