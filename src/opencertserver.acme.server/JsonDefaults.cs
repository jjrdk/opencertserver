using System.Text.Json.Serialization;
using CertesSlim.Json;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;
using OpenCertServer.Acme.Abstractions.Model;

namespace OpenCertServer.Acme.Server;

[JsonSourceGenerationOptions(UseStringEnumConverter = true, WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Account))]
[JsonSerializable(typeof(AcmeHeader))]
[JsonSerializable(typeof(JwsPayload))]
[JsonSerializable(typeof(CreateOrGetAccount))]
[JsonSerializable(typeof(CreateOrderRequest))]
[JsonSerializable(typeof(FinalizeOrderRequest))]
public partial class AcmeSerializerContext : JsonSerializerContext
{
}
