using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Abstractions.Model;

using System;

/// <summary>
/// Represents an ACME identifier, such as a DNS name, used in orders and authorizations.
/// </summary>
public sealed class Identifier
{
    private static readonly string[] SupportedTypes = ["dns"];

    /// <summary>
    /// Initializes a new instance of the <see cref="Identifier"/> class with the specified type and value.
    /// </summary>
    /// <param name="type">The identifier type (e.g., "dns").</param>
    /// <param name="value">The identifier value (e.g., domain name).</param>
    public Identifier(string type, string value)
    {
        Type = type;
        Value = value;
    }

    /// <summary>
    /// Gets or sets the identifier type (e.g., "dns"). Only supported types are allowed.
    /// </summary>
    /// <exception cref="MalformedRequestException">Thrown if the type is not supported.</exception>
    public string Type
    {
        get;
        set
        {
            var normalizedType = value.Trim().ToLowerInvariant();
            if (!SupportedTypes.Contains(normalizedType))
            {
                throw new MalformedRequestException($"Unsupported identifier type: {normalizedType}");
            }

            field = normalizedType;
        }
    } = null!;

    /// <summary>
    /// Gets or sets the identifier value (e.g., domain name). Value is normalized to lower case and trimmed.
    /// </summary>
    public string Value
    {
        get;
        set { field = value.Trim().ToLowerInvariant(); }
    } = null!;

    /// <summary>
    /// Gets a value indicating whether the identifier is a wildcard (starts with '*').
    /// </summary>
    public bool IsWildcard
    {
        get { return Value.StartsWith('*'); }
    }
}
