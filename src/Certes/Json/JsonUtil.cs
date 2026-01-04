using System.Text.Json.Serialization;
using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using Directory = Certes.Acme.Resource.Directory;

namespace Certes.Json;

/// <summary>
/// Defines the serializer context for Certes.
/// </summary>
[JsonSourceGenerationOptions(UseStringEnumConverter = true, WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Account))]
[JsonSerializable(typeof(Account.Payload))]
[JsonSerializable(typeof(AcmeError))]
[JsonSerializable(typeof(CertificateRevocation))]
[JsonSerializable(typeof(Directory))]
[JsonSerializable(typeof(Header))]
[JsonSerializable(typeof(JsonWebKey))]
[JsonSerializable(typeof(JwsPayload))]
[JsonSerializable(typeof(KeyChange))]
[JsonSerializable(typeof(ProtectedHeader))]
internal partial class CertesSerializerContext : JsonSerializerContext
{
}
