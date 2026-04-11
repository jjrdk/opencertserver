namespace OpenCertServer.Acme.Server.Endpoints;

using CertesSlim.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Extensions;

public static class RevocationEndpoints
{
    public static IEndpointRouteBuilder MapRevocationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/revoke-cert", async (
            JwsPayload payload,
            IRevocationService revocationService,
            CancellationToken cancellationToken) =>
        {
            var request = payload.ToPayload<RevokeCertificateRequest>();
            if (request == null)
            {
                throw new MalformedRequestException("The revocation request payload was empty or could not be read.");
            }

            await revocationService.RevokeCertificate(payload.ToAcmeHeader(), request, cancellationToken).ConfigureAwait(false);
            return Results.Ok();
        }).WithName("RevokeCert");

        return endpoints;
    }
}


