namespace OpenCertServer.Acme.Server;

using System.Text.Json.Serialization;
using CertesSlim.Json;

/// <summary>HTTP metadata for minimal API binding and responses in Native AOT hosts.</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UseStringEnumConverter = true)]
[JsonSerializable(typeof(JwsPayload))]
[JsonSerializable(typeof(Abstractions.HttpModel.Account), TypeInfoPropertyName = "HttpAccount")]
[JsonSerializable(typeof(Abstractions.HttpModel.Order), TypeInfoPropertyName = "HttpOrder")]
[JsonSerializable(typeof(Abstractions.HttpModel.Authorization), TypeInfoPropertyName = "HttpAuthorization")]
[JsonSerializable(typeof(Abstractions.HttpModel.Challenge), TypeInfoPropertyName = "HttpChallenge")]
[JsonSerializable(typeof(Abstractions.HttpModel.Directory), TypeInfoPropertyName = "HttpDirectory")]
[JsonSerializable(typeof(CertesSlim.Acme.AcmeError))]
[JsonSerializable(typeof(Dictionary<string, string[]>))]
public partial class AcmeHttpSerializerContext : JsonSerializerContext;
