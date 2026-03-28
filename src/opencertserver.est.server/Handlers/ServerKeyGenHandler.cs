using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Est.Server.Handlers;

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509Extensions;

internal static class ServerKeyGenHandler
{
    public static Task<IResult> Handle(
        ClaimsPrincipal user,
        ICertificateAuthority certificateAuthority,
        Stream body)
    {
        return HandleProfile("", user, certificateAuthority, body);
    }

    public static async Task<IResult> HandleProfile(
        [FromRoute] string profileName,
        ClaimsPrincipal user,
        ICertificateAuthority certificateAuthority,
        Stream body)
    {
        try
        {
            using var reader = new StreamReader(body, Encoding.UTF8);
            var request = await reader.ReadToEndAsync().ConfigureAwait(false);
            var signingRequest = request.StartsWith("-----BEGIN CERTIFICATE REQUEST-----")
                ? CertificateRequest.LoadSigningRequestPem(
                    request,
                    HashAlgorithmName.SHA256)
                : CertificateRequest.LoadSigningRequest(
                    request.Base64DecodeBytes(),
                    HashAlgorithmName.SHA256,
                    CertificateRequestLoadOptions.SkipSignatureValidation,
                    RSASignaturePadding.Pss);
            using var ecdsa = ECDsa.Create();
            signingRequest = new CertificateRequest(signingRequest.SubjectName, ecdsa, HashAlgorithmName.SHA256);
            var newCert =
                certificateAuthority.SignCertificateRequest(signingRequest, profileName,
                    user.Identity as ClaimsIdentity);
            if (newCert is SignCertificateResponse.Success success)
            {
                var mpr = new MultipartContent();
                mpr.Add(new ReadOnlyMemoryContent(ecdsa.ExportPkcs8PrivateKey())
                {
                    Headers =
                    {
                        { HeaderNames.ContentType, Constants.Pkcs8 },
                        { "Content-Transfer-Encoding", "base64" }
                    }
                });
                mpr.Add(new StringContent(success.Certificate.ToPemChain(success.Issuers))
                {
                    Headers =
                    {
                        { HeaderNames.ContentType, Constants.PemMimeType }
                    }
                });
                return new MultipartContentResult(mpr);
            }

            var error = (SignCertificateResponse.Error)newCert;
            return Results.Text(
                string.Join(Environment.NewLine, error.Errors), Constants.TextPlainMimeType,
                Encoding.UTF8,
                (int)HttpStatusCode.BadRequest);
        }
        catch (Exception)
        {
            return Results.Text(
                "An error occurred while processing the request.", Constants.TextPlainMimeType, Encoding.UTF8,
                (int)HttpStatusCode.BadRequest);
        }
    }
}

internal class MultipartContentResult : IResult
{
    private readonly MultipartContent _content;
    private readonly string _contentType;
    private readonly HttpStatusCode _statusCode;

    public MultipartContentResult(
        MultipartContent content,
        string contentType = Constants.MultiPartMixed,
        HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        _content = content;
        _contentType = contentType;
        _statusCode = statusCode;
    }

    public async Task ExecuteAsync(HttpContext ctx)
    {
        ctx.Response.StatusCode = (int)_statusCode;
        ctx.Response.ContentType = _contentType;
        await _content.CopyToAsync(ctx.Response.Body).ConfigureAwait(false);
        await ctx.Response.Body.FlushAsync().ConfigureAwait(false);
    }
}
