using System.Text;

namespace OpenCertServer.Est.Server.Handlers;

using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;

internal static class CaCertHandler
{
    public static IResult Handle(Func<string?, X509Certificate2Collection> certificates)
    {
        return HandleProfile("", certificates);
    }

    public static IResult HandleProfile(string profileName, Func<string?, X509Certificate2Collection> certificates)
    {
        var export = certificates(profileName).ExportCertificatePems();
        return Results.Text(export, Constants.PemMimeType, Encoding.UTF8, (int)HttpStatusCode.OK);
    }
}
