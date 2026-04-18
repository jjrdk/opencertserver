namespace OpenCertServer.Est.Server.Handlers;

using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using Microsoft.AspNetCore.Http;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Pkcs7;
using OpenCertServer.Est.Server;

internal static class CaCertsHandler
{
    public static Task<IResult> Handle(
        EstPublishedCertificatesResolver certificates,
        CancellationToken cancellationToken = default)
    {
        return HandleProfile("", certificates, cancellationToken);
    }

    public static async Task<IResult> HandleProfile(
        string profileName,
        EstPublishedCertificatesResolver certificates,
        CancellationToken cancellationToken = default)
    {
        EstInstruments.CaCertsRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = EstInstruments.ActivitySource.StartActivity(ActivityNames.CaCerts);
        activity?.AddTag(TagKeys.ProfileName, profileName);
        try
        {
            var export = await certificates(profileName, cancellationToken).ConfigureAwait(false);
            var signedData = new SignedData(version: 1, certificates: export.ToArray());
            var contentInfo = new CmsContentInfo(
                Oids.Pkcs7Signed.InitializeOid(Oids.Pkcs7SignedFriendlyName),
                signedData);
            var writer = new AsnWriter(AsnEncodingRules.DER);
            contentInfo.Encode(writer);
            var contentBytes = writer.Encode();
            EstInstruments.CaCertsSuccesses.Add(1);
            activity?.SetStatus(ActivityStatusCode.Ok);
            return Results.Text(Convert.ToBase64String(contentBytes), Constants.PkiMimeTypeCertsOnly,
                statusCode: (int)HttpStatusCode.OK);
        }
        catch (Exception ex)
        {
            EstInstruments.CaCertsFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            EstInstruments.CaCertsDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
        }
    }
}
