namespace OpenCertServer.Contrib.Intune;

using Microsoft.AspNetCore.Http;

/// <summary>
/// <c>POST /scep/intune/sync?dryRun=true|false</c>: runs the revocation sync and returns the
/// report; 409 while another run is in progress.
/// </summary>
public static class SyncHandler
{
    public static async Task<IResult> Handle(
        IntuneRevocationSync sync,
        bool dryRun,
        CancellationToken cancellationToken)
    {
        var report = await sync.Run(dryRun, cancellationToken).ConfigureAwait(false);
        return Results.Json(
            report,
            IntuneJsonContext.Default.SyncReport,
            statusCode: report.AlreadyRunning ? StatusCodes.Status409Conflict : StatusCodes.Status200OK);
    }
}
