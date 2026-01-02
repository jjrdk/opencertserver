using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca;

namespace opencertserver.ca.server.Handlers;

public static class CrlHandler
{
    public static async Task Handle(HttpContext context)
    {
        var ca = context.RequestServices.GetRequiredService<ICertificateAuthority>();
        var crl = ca.GetRevocationList();
        context.Response.ContentType = "application/pkix-crl";
        var writer = context.Response.BodyWriter;
        await writer.WriteAsync(crl);
        await writer.CompleteAsync();
        await writer.FlushAsync();
    }
}
