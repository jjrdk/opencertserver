using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Abstractions.Model;

using System;

public sealed class Identifier
{
    private static readonly string[] SupportedTypes = ["dns"];

    private string _type = null!;
    private string _value = null!;

    public Identifier(string type, string value)
    {
        Type = type;
        Value = value;
    }

    public string Type
    {
        get { return _type; }
        set
        {
            var normalizedType = value.Trim().ToLowerInvariant();
            if (!SupportedTypes.Contains(normalizedType))
            {
                throw new MalformedRequestException($"Unsupported identifier type: {normalizedType}");
            }

            _type = normalizedType;
        }
    }

    public string Value
    {
        get { return _value; }
        set { _value = value.Trim().ToLowerInvariant(); }
    }

    public bool IsWildcard
    {
        get { return Value.StartsWith('*'); }
    }
}
