using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using Ocsm = OpenCertServer.Acme.Abstractions.Model;

namespace OpenCertServer.Data.Serialization;

using System.Text.Json.Serialization;

/// <summary>
/// Source-generated serialization metadata for persisted ACME aggregates.
/// </summary>
[JsonSourceGenerationOptions(
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Ocsm.Account))]
[JsonSerializable(typeof(Ocsm.Order))]
[JsonSerializable(typeof(Ocsm.Authorization))]
[JsonSerializable(typeof(Ocsm.Challenge))]
[JsonSerializable(typeof(Identifier))]
[JsonSerializable(typeof(AcmeError))]
[JsonSerializable(typeof(JsonWebKey))]
internal partial class DataSerializerContext : JsonSerializerContext
{
}
