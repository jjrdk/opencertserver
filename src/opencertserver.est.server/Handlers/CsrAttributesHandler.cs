using System.Diagnostics.CodeAnalysis;

namespace OpenCertServer.Est.Server.Handlers;

using System.Formats.Asn1;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using OpenCertServer.Ca.Utils.X509.Templates;

[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
public abstract class CsrAttributesHandler
{
    public async Task Handle(HttpContext ctx)
    {
        var template = await GetTemplate(ctx.User).ConfigureAwait(false);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        template.Encode(writer);
        var encoded = writer.Encode();
        ctx.Response.ContentType = "application/csrattrs";
        ctx.Response.StatusCode = (int)HttpStatusCode.OK;
        ctx.Response.Headers[HeaderNames.TransferEncoding] = "base64";
        ctx.Response.Headers["Content-Transfer-Encoding"] = "base64";
        await ctx.Response.Body.WriteAsync(encoded).ConfigureAwait(false);
        await ctx.Response.CompleteAsync().ConfigureAwait(false);
    }

    public abstract Task<CertificateSigningRequestTemplate> GetTemplate(ClaimsPrincipal user);
}
