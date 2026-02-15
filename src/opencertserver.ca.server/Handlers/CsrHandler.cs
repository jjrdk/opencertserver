namespace OpenCertServer.Ca.Server.Handlers;

using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509Extensions;

public static class CsrHandler
{
    public static async Task Handle(HttpContext ctx)
    {
        var ca = ctx.RequestServices.GetRequiredService<ICertificateAuthority>();
        using var reader = new StreamReader(ctx.Request.Body);
        var csrPem = await reader.ReadToEndAsync();
        var certResponse = ca.SignCertificateRequestPem(csrPem);
        if (certResponse is SignCertificateResponse.Success success)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            ctx.Response.ContentType = Constants.PemMimeType;
            await using var writer = new StreamWriter(ctx.Response.Body);
            var pem = success.Certificate.ToPemChain(success.Issuers);
            success.Certificate.Dispose();
            foreach (var issuer in success.Issuers)
            {
                issuer.Dispose();
            }
            await writer.WriteLineAsync(pem).ConfigureAwait(false);
            await writer.FlushAsync().ConfigureAwait(false);
        }
        else
        {
            var error = (SignCertificateResponse.Error)certResponse;
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
