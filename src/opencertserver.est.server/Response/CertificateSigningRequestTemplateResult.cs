using System.Formats.Asn1;
using System.Net;
using Microsoft.AspNetCore.Http;
using OpenCertServer.Ca.Utils;

namespace OpenCertServer.Est.Server.Response;

internal class CertificateSigningRequestTemplateResult : IResult
{
    private readonly CsrAttributesResponse _response;

    public CertificateSigningRequestTemplateResult(CsrAttributesResponse response)
    {
        _response = response;
    }

    public async Task ExecuteAsync(HttpContext ctx)
    {
        if (_response.StatusCode != HttpStatusCode.OK || _response.Attributes is not { HasValues: true } attributes)
        {
            ctx.Response.StatusCode = (int)_response.StatusCode;
            await ctx.Response.CompleteAsync().ConfigureAwait(false);
            return;
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        attributes.Encode(writer);
        var encoded = writer.Encode().Base64Encode();
        ctx.Response.ContentType = "application/csrattrs";
        ctx.Response.StatusCode = (int)_response.StatusCode;
        await ctx.Response.WriteAsync(encoded).ConfigureAwait(false);
        await ctx.Response.CompleteAsync().ConfigureAwait(false);
    }
}
