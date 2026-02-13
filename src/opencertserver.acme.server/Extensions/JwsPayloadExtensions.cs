using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using CertesSlim.Json;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;

namespace OpenCertServer.Acme.Server.Extensions;

public static class JwsPayloadExtensions
{
    extension(JwsPayload payload)
    {
        public AcmeHeader ToAcmeHeader()
        {
            return JsonSerializer.Deserialize<AcmeHeader>(Base64UrlEncoder.Decode(payload.Protected)!,
                AcmeSerializerContext.Default.AcmeHeader)!;
        }

        public T? ToPayload<T>()
        {
            return JsonSerializer.Deserialize(
                Base64UrlEncoder.Decode(payload.Payload),
                (JsonTypeInfo<T>)AcmeSerializerContext.Default.GetTypeInfo(typeof(T))!)!;
        }
    }
}
