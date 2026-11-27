namespace OpenCertServer.Host.Unified;

using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;

[JsonSerializable(typeof(ProblemDetails))]
[JsonSerializable(typeof(string))]
[JsonSerializable(typeof(bool))]
internal partial class ApplianceJsonContext : JsonSerializerContext;
