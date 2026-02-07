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

internal class ServerKeyGenHandler
{
    private readonly ICertificateAuthority _certificateAuthority;

    public ServerKeyGenHandler(ICertificateAuthority certificateAuthority)
    {
        _certificateAuthority = certificateAuthority;
    }

    public async Task Handle(HttpContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
        var request = await reader.ReadToEndAsync().ConfigureAwait(false);
        var csr = request.Base64DecodeBytes();
        var signingRequest = CertificateRequest.LoadSigningRequest(
            csr,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.SkipSignatureValidation,
            RSASignaturePadding.Pss);
        using var ecdsa = ECDsa.Create();
        signingRequest = new CertificateRequest(signingRequest.SubjectName, ecdsa, HashAlgorithmName.SHA256);
        var newCert = _certificateAuthority.SignCertificateRequest(signingRequest);
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
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            ctx.Response.ContentType = Constants.MultiPartMixed;
            await mpr.CopyToAsync(ctx.Response.Body);
            await ctx.Response.Body.FlushAsync().ConfigureAwait(false);
            success.Certificate.Dispose();
            foreach (var issuer in success.Issuers)
            {
                issuer.Dispose();
            }
        }
        else
        {
            var error = (SignCertificateResponse.Error)newCert;
            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            ctx.Response.ContentType = Constants.TextPlainMimeType;
            await using var writer = new StreamWriter(ctx.Response.Body);
            foreach (var line in error.Errors)
            {
                await writer.WriteLineAsync(line).ConfigureAwait(false);
            }

            await writer.FlushAsync().ConfigureAwait(false);
        }
    }
}
