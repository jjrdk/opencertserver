namespace OpenCertServer.Acme.Server.Endpoints;

using System.Diagnostics;
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
            AcmeInstruments.RevokeRequests.Add(1);
            var sw = Stopwatch.GetTimestamp();
            using var activity = AcmeInstruments.ActivitySource.StartActivity(ActivityNames.Revoke);
            try
            {
                var request = payload.ToPayload<RevokeCertificateRequest>();
                if (request == null)
                {
                    throw new MalformedRequestException("The revocation request payload was empty or could not be read.");
                }

                await revocationService.RevokeCertificate(payload.ToAcmeHeader(), request, cancellationToken).ConfigureAwait(false);
                AcmeInstruments.RevokeSuccesses.Add(1);
                activity?.SetStatus(ActivityStatusCode.Ok);
                AcmeInstruments.RevokeDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
                return Results.Ok();
            }
            catch (Exception ex)
            {
                AcmeInstruments.RevokeFailures.Add(1);
                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                AcmeInstruments.RevokeDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
                throw;
            }
        }).WithName("RevokeCert");

        return endpoints;
    }
}
