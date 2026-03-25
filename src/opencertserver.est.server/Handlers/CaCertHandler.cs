namespace OpenCertServer.Est.Server.Handlers;

using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

internal sealed class CaCertHandler
{
    private readonly X509Certificate2Collection _certificateStore;

    public CaCertHandler(X509Certificate2Collection certificateStore)
    {
        _certificateStore = certificateStore;
    }

    public async Task Handle(HttpContext ctx)
    {
        var export = _certificateStore.ExportCertificatePems();

        ctx.Response.StatusCode = (int)HttpStatusCode.OK;
        ctx.Response.ContentType = Constants.PemMimeType;
        var bodyWriter = new StreamWriter(ctx.Response.Body);
        await bodyWriter.WriteAsync(export).ConfigureAwait(false);
        await bodyWriter.FlushAsync().ConfigureAwait(false);
    }
}
