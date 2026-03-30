namespace OpenCertServer.Est.Server.Handlers;

using System.Formats.Asn1;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
        ICertificateAuthority certificateAuthority)
    {
        return HandleProfile(context, user, certificateAuthority, "");
    }

    public static async Task<IResult> HandleProfile(
        HttpContext context,
        ClaimsPrincipal user,
        ICertificateAuthority certificateAuthority,
        [FromRoute] string profileName)
    {
        var connection = context.Connection;
        var cert = await connection.GetClientCertificateAsync().ConfigureAwait(false);

        if (cert == null)
        {
            return Results.BadRequest();
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

        var newCert = certificateAuthority.SignCertificateRequest(
            request,
            profileName,
            user.Identity as ClaimsIdentity,
            cert);
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
        var signedResponse = new SignedData(version: 4, certificates: content.Concat(success.Issuers).ToArray());
        var writer = new AsnWriter(AsnEncodingRules.DER);
        signedResponse.Encode(writer);
        var derBytes = writer.Encode();
        return Results.Bytes(derBytes, Constants.PemMimeType);
    }
}
