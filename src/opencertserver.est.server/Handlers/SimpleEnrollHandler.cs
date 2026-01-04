using OpenCertServer.Ca.Utils;

namespace OpenCertServer.Est.Server.Handlers;

using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Ca;

internal sealed class SimpleEnrollHandler
{
    private readonly ICertificateAuthority _certificateAuthority;

    public SimpleEnrollHandler(ICertificateAuthority certificateAuthority)
    {
        _certificateAuthority = certificateAuthority;
    }

    public async Task Handle(HttpContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
        var request = await reader.ReadToEndAsync().ConfigureAwait(false);
        var newCert = _certificateAuthority.SignCertificateRequest(request);
        if (newCert is SignCertificateResponse.Success success)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            ctx.Response.ContentType = Constants.PemMimeType;
            await using var writer = new StreamWriter(ctx.Response.Body);
            var pem = success.Certificate.ToPemChain(success.Issuers);
            success.Certificate.Dispose();
            await writer.WriteLineAsync(pem).ConfigureAwait(false);
            await writer.FlushAsync().ConfigureAwait(false);
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
