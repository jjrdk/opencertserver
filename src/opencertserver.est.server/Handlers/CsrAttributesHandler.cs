using OpenCertServer.Est.Server.Response;

namespace OpenCertServer.Est.Server.Handlers;

using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;

public static class CsrAttributesHandler
{
    public static Task<IResult> Handle(
        ClaimsPrincipal? user,
        ICsrTemplateLoader loader,
        CancellationToken cancellationToken = default)
    {
        return HandleProfile("", user, loader, cancellationToken);
    }

    public static async Task<IResult> HandleProfile(
        string? profileName,
        ClaimsPrincipal? user,
        ICsrTemplateLoader loader,
        CancellationToken cancellationToken = default)
    {
        EstInstruments.CsrAttrsRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = EstInstruments.ActivitySource.StartActivity(ActivityNames.CsrAttrs);
        activity?.AddTag(TagKeys.Profile, profileName);
        try
        {
            var attributes = await loader.GetTemplate(profileName, user, cancellationToken).ConfigureAwait(false);
            EstInstruments.CsrAttrsSuccesses.Add(1);
            activity?.SetStatus(ActivityStatusCode.Ok);
            return new CertificateSigningRequestTemplateResult(attributes);
        }
        catch (Exception ex)
        {
            EstInstruments.CsrAttrsFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            EstInstruments.CsrAttrsDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
        }
    }
}
