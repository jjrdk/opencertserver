using System.Formats.Asn1;
using System.Net;
using Microsoft.AspNetCore.Http;
using OpenCertServer.Ca.Utils;
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
        var encoded = writer.Encode().Base64Encode();
        ctx.Response.ContentType = "application/csrattrs";
        ctx.Response.StatusCode = (int)HttpStatusCode.OK;
        await ctx.Response.WriteAsync(encoded).ConfigureAwait(false);
        await ctx.Response.CompleteAsync().ConfigureAwait(false);
    }
}
