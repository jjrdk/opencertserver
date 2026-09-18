namespace CertesSlim.Acme.Resource;

using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// Represents type of <see cref="Identifier"/>.
/// </summary>
[JsonConverter(typeof(IdentifierTypeConverter))]
public enum IdentifierType
{
    /// <summary>
    /// The DNS type.
    /// </summary>
    [EnumMember(Value = "dns")] Dns
}

/// <summary>
/// Serializes <see cref="IdentifierType"/> using the lower-case tokens defined
/// in RFC 8555 (e.g. <c>dns</c>), independent of any naming policy in effect.
/// </summary>
[UnconditionalSuppressMessage("Trimming", "IL2026", Justification = "Manual converter, no reflection.")]
public sealed class IdentifierTypeConverter : JsonConverter<IdentifierType>
{
    /// <inheritdoc />
    public override IdentifierType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return reader.GetString() switch
        {
            "dns" => IdentifierType.Dns,
            _ => throw new JsonException($"Unknown identifier type '{reader.GetString()}'.")
        };
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, IdentifierType value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value switch
        {
            IdentifierType.Dns => "dns",
            _ => throw new JsonException($"Unknown identifier type '{value}'.")
        });
    }
}
