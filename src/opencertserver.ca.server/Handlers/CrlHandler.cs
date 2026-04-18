using Microsoft.AspNetCore.Mvc;

namespace OpenCertServer.Ca.Server.Handlers;

using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using OpenCertServer.Ca.Utils.Ca;

public static class CrlHandler
{
    public static Task<IResult> Handle(ICertificateAuthority ca)
    {
        return HandleProfile("", ca);
    }

    public static async Task<IResult> HandleProfile([FromRoute] string profileName, ICertificateAuthority ca)
    {
        CaInstruments.CrlRequests.Add(1);
        CaInstruments.CrlGenerationRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = CaInstruments.ActivitySource.StartActivity(ActivityNames.CrlRequest);
        try
        {
            var crl = await ca.GetRevocationList(profileName).ConfigureAwait(false);
            CaInstruments.CrlSuccesses.Add(1);
            CaInstruments.CrlGenerationSuccesses.Add(1);
            activity?.SetStatus(ActivityStatusCode.Ok);
            return Results.Bytes(crl, "application/pkix-crl");
        }
        catch (Exception ex)
        {
            CaInstruments.CrlFailures.Add(1);
            CaInstruments.CrlGenerationFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            var elapsed = Stopwatch.GetElapsedTime(sw).TotalSeconds;
            CaInstruments.CrlDuration.Record(elapsed);
            CaInstruments.CrlGenerationDuration.Record(elapsed);
        }
    }
}
