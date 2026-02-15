namespace OpenCertServer.Ca.Server.Handlers;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;

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
