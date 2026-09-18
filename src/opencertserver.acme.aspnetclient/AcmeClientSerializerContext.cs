namespace OpenCertServer.Acme.AspNetClient;

using System.Text.Json.Serialization;
using OpenCertServer.Acme.AspNetClient.Persistence;

[JsonSourceGenerationOptions(WriteIndented = false, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ChallengeDto))]
[JsonSerializable(typeof(ChallengeDto[]))]
internal partial class AcmeClientSerializerContext : JsonSerializerContext
{
}
