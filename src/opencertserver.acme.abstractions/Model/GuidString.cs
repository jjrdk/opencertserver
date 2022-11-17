namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using Microsoft.IdentityModel.Tokens;

public sealed class GuidString
{
    private GuidString()
    {
        Value = Base64UrlEncoder.Encode(Guid.NewGuid().ToByteArray());
    }

    private string Value { get; }

    public static string NewValue() => new GuidString().Value;
}