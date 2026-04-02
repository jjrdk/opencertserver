namespace OpenCertServer.Est.Server.Handlers;

using System.Formats.Asn1;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Ca.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Pkcs7;
using OpenCertServer.Ca.Utils.X509Extensions;

internal static class SimpleReEnrollHandler
{
    public static Task<IResult> Handle(
        HttpContext context,
        ClaimsPrincipal user,
        ICertificateAuthority certificateAuthority,
        CancellationToken cancellationToken)
    {
        return HandleProfile(context, user, certificateAuthority, "", cancellationToken);
    }

    public static async Task<IResult> HandleProfile(
        HttpContext context,
        ClaimsPrincipal user,
        ICertificateAuthority certificateAuthority,
        [FromRoute] string profileName,
        CancellationToken cancellationToken)
    {
        var connection = context.Connection;
        var cert = await connection.GetClientCertificateAsync(cancellationToken).ConfigureAwait(false);
        using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
        var requestBody = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);

        if (cert == null)
        {
            return Results.BadRequest();
        }

        if (!requestBody.TryVerifyTlsUniqueValue(out var proofOfPossessionError))
        {
            return Results.Text(proofOfPossessionError, Constants.TextPlainMimeType, Encoding.UTF8,
                (int)HttpStatusCode.BadRequest);
        }

        var request = cert.PublicKey.Oid.Value switch
        {
            Oids.EcPublicKey => new CertificateRequest(
                cert.SubjectName,
                cert.GetECDsaPublicKey()!,
                HashAlgorithmName.SHA256),
            Oids.Rsa => new CertificateRequest(
                cert.SubjectName,
                cert.GetRSAPublicKey()!,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss),
            _ => null
        };
        if (request == null)
        {
            return Results.BadRequest();
        }

        foreach (var extension in cert.Extensions)
        {
            request.CertificateExtensions.Add(extension);
        }

        var newCert = await certificateAuthority.SignCertificateRequest(
            request,
            profileName,
            user.Identity as ClaimsIdentity,
            cert, cancellationToken).ConfigureAwait(false);
        if (newCert is not SignCertificateResponse.Success success)
        {
            return Results.BadRequest();
        }

        var responseType = context.Request.GetTypedHeaders().Accept;
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
}
