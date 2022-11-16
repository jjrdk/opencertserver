namespace OpenCertServer.Acme.Server.Middleware;

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Abstractions.HttpModel.Requests;
using Microsoft.AspNetCore.Http;

public static class AcmeRequestReader
{
    [RequiresUnreferencedCode($"Uses {nameof(AcmeRawPostRequest)}")]
    public static async Task<AcmeRawPostRequest?> ReadAcmeRequest(this HttpRequest request)
    {
        var result = await JsonSerializer.DeserializeAsync<AcmeRawPostRequest>(request.Body);
        return result;
    }
}