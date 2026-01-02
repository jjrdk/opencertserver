using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca;

namespace opencertserver.ca.server.Handlers;

public static class RevocationHandler
{
    public static async Task Handle(HttpContext context)
    {
        var serialNumberHex = context.Request.Query["sn"].ToString();
        if (string.IsNullOrEmpty(serialNumberHex)
         || !Enum.TryParse(context.Request.Query["reason"].ToString(), true,
                out X509RevocationReason reason))
        {
            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            await context.Response.CompleteAsync();
            return;
        }

        var ca = context.RequestServices.GetRequiredService<ICertificateAuthority>();
        var result = ca.RevokeCertificate(serialNumberHex, reason);
        context.Response.StatusCode = result ? (int)HttpStatusCode.OK : (int)HttpStatusCode.NotFound;
        await context.Response.CompleteAsync();
    }
}
