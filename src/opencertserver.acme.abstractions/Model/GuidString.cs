namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Provides a base64url-encoded GUID string generator for use as unique identifiers.
/// </summary>
public sealed class GuidString
{
    /// <summary>
    /// Initializes a new instance of the <see cref="GuidString"/> class and generates a new value.
    /// </summary>
    private GuidString()
    {
        Value = Base64UrlEncoder.Encode(Guid.NewGuid().ToByteArray());
    }

    /// <summary>
    /// Gets the generated base64url-encoded GUID value.
    /// </summary>
    private string Value { get; }

    /// <summary>
    /// Generates a new base64url-encoded GUID string.
    /// </summary>
    /// <returns>A new unique string value.</returns>
    public static string NewValue() => new GuidString().Value;
}
