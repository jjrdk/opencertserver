namespace OpenCertServer.Acme.Yarp;

using System.Text.Json.Serialization;

/// <summary>
/// Source-generated <see cref="System.Text.Json.JsonSerializerContext"/> for
/// <see cref="RouteAcmeOptions"/>. Using source generation keeps the YARP ACME metadata
/// serialization AOT- and trimming-compatible.
/// </summary>
[JsonSourceGenerationOptions(
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(RouteAcmeOptions))]
[JsonSerializable(typeof(RouteAcmeOptions[]))]
internal partial class RouteAcmeOptionsSerializerContext : JsonSerializerContext
{
}
