using System.Formats.Asn1;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using OpenCertServer.Ca.Utils.X509.Templates;

namespace OpenCertServer.Est.Server.Handlers;

internal class CertificateSigningRequestTemplateResult : IResult
{
    private readonly CertificateSigningRequestTemplate _template;

    public CertificateSigningRequestTemplateResult(CertificateSigningRequestTemplate template)
    {
        _template = template;
    }

    public async Task ExecuteAsync(HttpContext ctx)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        _template.Encode(writer);
        var encoded = writer.Encode();
        ctx.Response.ContentType = "application/csrattrs";
        ctx.Response.StatusCode = (int)HttpStatusCode.OK;
        ctx.Response.Headers[HeaderNames.TransferEncoding] = "base64";
        ctx.Response.Headers["Content-Transfer-Encoding"] = "base64";
        await ctx.Response.Body.WriteAsync(encoded).ConfigureAwait(false);
        await ctx.Response.CompleteAsync().ConfigureAwait(false);
    }
}
