namespace OpenCertServer.Est.Server.Handlers;

using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using OpenCertServer.Ca.Utils;
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
        var signedData = new SignedData(version: 1, certificates: export.ToArray());
        var writer = new AsnWriter(AsnEncodingRules.DER);
        signedData.Encode(writer);
        var signedEncoded = writer.Encode();
        writer.Reset();
        var contentInfo = new CmsContentInfo(
            Oids.Pkcs7Signed.InitializeOid(Oids.Pkcs7SignedFriendlyName),
            signedEncoded);
        contentInfo.Encode(writer);
        var contentBytes = writer.Encode();
        return Results.Text(Convert.ToBase64String(contentBytes), Constants.PemMimeType,
            statusCode: (int)HttpStatusCode.OK);
    }
}
