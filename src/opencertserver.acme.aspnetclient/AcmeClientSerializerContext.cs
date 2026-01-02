using System.Text.Json.Serialization;
using OpenCertServer.Acme.AspNetClient.Persistence;

namespace OpenCertServer.Acme.AspNetClient;

[JsonSourceGenerationOptions(WriteIndented = false, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ChallengeDto))]
[JsonSerializable(typeof(ChallengeDto[]))]
internal partial class AcmeClientSerializerContext : JsonSerializerContext
{
}
