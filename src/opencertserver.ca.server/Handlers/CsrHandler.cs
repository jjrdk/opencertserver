using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace OpenCertServer.Ca.Server.Handlers;

using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Http;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509Extensions;

public static class CsrHandler
{
    public static async Task<IResult> Handle(
        [FromRoute] string? profileName,
        ClaimsPrincipal user,
        ICertificateAuthority ca,
        [FromBody] Stream body,
        CancellationToken cancellationToken)
    {
        CaInstruments.CsrRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = CaInstruments.ActivitySource.StartActivity(ActivityNames.CsrSign);
        try
        {
            using var reader = new StreamReader(body);
            var csrPem = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            var certResponse = await ca.SignCertificateRequestPem(csrPem, profileName, user.Identity as ClaimsIdentity,
                cancellationToken: cancellationToken);
            if (certResponse is SignCertificateResponse.Success success)
            {
                CaInstruments.CsrSuccesses.Add(1);
                activity?.SetStatus(ActivityStatusCode.Ok);
                return Results.Text(success.Certificate.ToPemChain(success.Issuers), Constants.PemMimeType);
            }

            var error = (SignCertificateResponse.Error)certResponse;
            CaInstruments.CsrFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error);
            return Results.Text(
                string.Join(Environment.NewLine, error.Errors),
                Constants.TextPlainMimeType,
                Encoding.UTF8,
                (int)HttpStatusCode.BadRequest);
        }
        catch (Exception ex)
        {
            CaInstruments.CsrFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            CaInstruments.CsrDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
        }
    }
}
