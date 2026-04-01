using System.Net;

namespace OpenCertServer.Est.Server.Handlers;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using OpenCertServer.Ca.Utils.Pkcs7;

internal static class CaCertsHandler
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
        var export = await certificates(profileName, cancellationToken).ConfigureAwait(false);
        var signedData = new SignedData(version: 4, certificates: export.ToArray());
        var writer = new AsnWriter(AsnEncodingRules.DER);
        signedData.Encode(writer);
        return Results.Text(Convert.ToBase64String(writer.Encode()), Constants.PemMimeType,
            statusCode: (int)HttpStatusCode.OK);
    }
}
