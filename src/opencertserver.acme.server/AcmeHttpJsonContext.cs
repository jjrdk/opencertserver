namespace OpenCertServer.Acme.Server;

using System.Text.Json.Serialization;
using CertesSlim.Acme;
using CertesSlim.Json;
using OpenCertServer.Acme.Abstractions.HttpModel;

[JsonSourceGenerationOptions(
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(JwsPayload))]
[JsonSerializable(typeof(AcmeError))]
[JsonSerializable(typeof(Account), TypeInfoPropertyName = "HttpAccount")]
[JsonSerializable(typeof(AccountOrders))]
[JsonSerializable(typeof(Authorization), TypeInfoPropertyName = "HttpAuthorization")]
[JsonSerializable(typeof(Challenge), TypeInfoPropertyName = "HttpChallenge")]
[JsonSerializable(typeof(Directory))]
[JsonSerializable(typeof(Order), TypeInfoPropertyName = "HttpOrder")]
internal partial class AcmeHttpJsonContext : JsonSerializerContext;
