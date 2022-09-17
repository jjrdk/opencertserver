namespace OpenCertServer.Est.Server.Handlers
{
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
            var export = _certificateStore.Export(X509ContentType.Pkcs7);

            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            ctx.Response.ContentType = Constants.Pkcs7MimeType;
            var bodyWriter = ctx.Response.BodyWriter;
            await bodyWriter.WriteAsync(export).ConfigureAwait(false);
            await bodyWriter.FlushAsync().ConfigureAwait(false);
            await bodyWriter.CompleteAsync().ConfigureAwait(false);
        }
    }
}