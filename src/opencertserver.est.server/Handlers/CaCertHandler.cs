using System.Text;

namespace OpenCertServer.Est.Server.Handlers;

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;

internal static class CaCertHandler
{
    public static Task<IResult> Handle(
        Func<string?, CancellationToken, Task<X509Certificate2Collection>> certificates,
        CancellationToken cancellationToken = default)
    {
        return HandleProfile("", certificates, cancellationToken);
    }

    public static async Task<IResult> HandleProfile(
        string profileName,
        Func<string?, CancellationToken, Task<X509Certificate2Collection>> certificates,
        CancellationToken cancellationToken = default)
    {
        var export = (await certificates(profileName, cancellationToken).ConfigureAwait(false)).ExportCertificatePems();
        return Results.Text(export, Constants.PemMimeType, Encoding.UTF8, (int)HttpStatusCode.OK);
    }
}
