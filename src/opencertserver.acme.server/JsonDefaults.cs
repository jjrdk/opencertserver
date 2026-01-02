using System.Text.Json.Serialization;
using OpenCertServer.Acme.Abstractions.Model;

namespace OpenCertServer.Acme.Server;

[JsonSourceGenerationOptions(UseStringEnumConverter = true, WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Account))]
public partial class AcmeSerializerContext : JsonSerializerContext
{
}
