using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509Extensions;

namespace OpenCertServer.Est.Server.Handlers;

using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

internal static class SimpleEnrollHandler
{
    public static Task<IResult> Handle(
        ClaimsPrincipal? user,
        Stream body,
        ICertificateAuthority certificateAuthority)
    {
        return HandleProfile("", user, body, certificateAuthority);
    }

    public static async Task<IResult> HandleProfile(
        [FromRoute] string profileName,
        ClaimsPrincipal? user,
        Stream body,
        ICertificateAuthority certificateAuthority)
    {
        using var reader = new StreamReader(body, Encoding.UTF8);
        var request = await reader.ReadToEndAsync().ConfigureAwait(false);
        var newCert =
            certificateAuthority.SignCertificateRequestPem(
                request,
                profileName,
                user?.Identity as ClaimsIdentity);
        if (newCert is SignCertificateResponse.Success success)
        {
            return Results.Text(success.Certificate.ToPemChain(success.Issuers), Constants.PemMimeType);
        }

        var error = (SignCertificateResponse.Error)newCert;
        return Results.Text(string.Join(Environment.NewLine, error.Errors), Constants.PemMimeType, Encoding.UTF8,
            (int)HttpStatusCode.BadRequest);
    }
}
