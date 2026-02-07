using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualBasic;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Ca.Server.Handlers;

public static class CrlHandler
{
    public static async Task Handle(HttpContext context)
    {
        var ca = context.RequestServices.GetRequiredService<ICertificateAuthority>();
        var crl = await ca.GetRevocationList();
        context.Response.ContentType = "application/pkix-crl";
        var writer = context.Response.BodyWriter;
        await writer.WriteAsync(crl);
        await writer.CompleteAsync();
        await writer.FlushAsync();
    }
}
