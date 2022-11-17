namespace OpenCertServer.Acme.Abstractions.HttpModel.Converters;

using System;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Model;

public sealed class JwkConverter : JsonConverter<Jwk>
{
    public override Jwk Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var obj = JsonNode.Parse(ref reader) ?? throw new InvalidOperationException("Invalid content");
        return new Jwk(obj.ToJsonString());
    }

    public override void Write(Utf8JsonWriter writer, Jwk value, JsonSerializerOptions options)
    {
        throw new NotImplementedException();
    }
}