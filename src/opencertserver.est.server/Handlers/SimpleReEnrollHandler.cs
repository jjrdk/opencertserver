using Microsoft.AspNetCore.Mvc;

namespace OpenCertServer.Est.Server.Handlers;

using System.Security.Claims;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509Extensions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Ca.Utils;
using Microsoft.AspNetCore.Http;

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
        var cert = await connection.GetClientCertificateAsync();

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

        var pem = success.Certificate.ToPemChain(success.Issuers);
        await certificateAuthority.RevokeCertificate(cert.GetSerialNumberString(), X509RevocationReason.Superseded);
        return Results.Text(pem, Constants.PemMimeType);
    }
}
