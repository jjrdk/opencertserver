namespace OpenCertServer.Data.Serialization;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>Source-generated serialization metadata for persisted CA profiles.</summary>
[JsonSourceGenerationOptions(
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(CaProfileDocument))]
internal partial class CaProfileSerializerContext : JsonSerializerContext
{
}
