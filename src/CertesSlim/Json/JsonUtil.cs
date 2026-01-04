using System.Text.Json.Serialization;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using Directory = CertesSlim.Acme.Resource.Directory;

namespace CertesSlim.Json;

/// <summary>
/// Defines the serializer context for CertesSlim.
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
