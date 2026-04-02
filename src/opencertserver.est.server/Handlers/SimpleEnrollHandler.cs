using OpenCertServer.Ca.Utils;

namespace OpenCertServer.Est.Server.Handlers;

using System.Formats.Asn1;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Pkcs7;
using OpenCertServer.Ca.Utils.X509Extensions;

internal static class SimpleEnrollHandler
{
    public static Task<IResult> Handle(
        ClaimsPrincipal? user,
        HttpRequest httpRequest,
        ICertificateAuthority certificateAuthority,
        CancellationToken cancellationToken)
    {
        return HandleProfile("", certificateAuthority, httpRequest, user,  cancellationToken);
    }

    public static async Task<IResult> HandleProfile(
        [FromRoute] string profileName,
        ICertificateAuthority certificateAuthority,
        HttpRequest httpRequest,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
    {
        var body = httpRequest.Body;
        var responseType = httpRequest.GetTypedHeaders().Accept;
        using var reader = new StreamReader(body, Encoding.UTF8);
        var requestContent = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        if (!requestContent.TryVerifyTlsUniqueValue(out var proofOfPossessionError))
        {
            return Results.Text(proofOfPossessionError, Constants.TextPlainMimeType, Encoding.UTF8,
                (int)HttpStatusCode.BadRequest);
        }

        var newCert =
            await certificateAuthority.SignCertificateRequestPem(
                requestContent,
                profileName,
                user?.Identity as ClaimsIdentity,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        if (newCert is SignCertificateResponse.Success success)
        {
            // This is a deviation from the RFC but is easier to parse.
            if (responseType.Any(x =>
                x.MediaType.HasValue &&
                x.MediaType.Value.Equals(Constants.PemFile, StringComparison.OrdinalIgnoreCase)))
            {
                return Results.Text(success.Certificate.ToPemChain(success.Issuers), Constants.PemFile);
            }

            X509Certificate2[] content = [success.Certificate];
            var signedResponse = new SignedData(version: 1, certificates: content.Concat(success.Issuers).ToArray());
            var writer = new AsnWriter(AsnEncodingRules.DER);
            signedResponse.Encode(writer);
            var derBytes = writer.Encode();
            writer.Reset();
            var contentInfo = new CmsContentInfo(
                Oids.Pkcs7Signed.InitializeOid(Oids.Pkcs7SignedFriendlyName),
                derBytes);
            contentInfo.Encode(writer);
            var contentBytes = writer.Encode();
            return Results.Text(contentBytes, Constants.PemMimeType);
        }

        var error = (SignCertificateResponse.Error)newCert;
        return Results.Text(string.Join(Environment.NewLine, error.Errors), Constants.TextPlainMimeType, Encoding.UTF8,
            (int)HttpStatusCode.BadRequest);
    }
}
