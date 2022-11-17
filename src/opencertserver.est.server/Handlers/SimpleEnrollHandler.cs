namespace OpenCertServer.Est.Server.Handlers
{
    using System;
    using System.IO;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;
    using OpenCertServer.Ca;

    internal sealed class SimpleEnrollHandler
    {
        private readonly ICertificateAuthority _certificateAuthority;

        public SimpleEnrollHandler(ICertificateAuthority certificateAuthority)
        {
            _certificateAuthority = certificateAuthority;
        }

        public async Task Handle(HttpContext ctx)
        {
            using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
            var request = await reader.ReadToEndAsync().ConfigureAwait(false);
            var newCert = _certificateAuthority.SignCertificateRequest(request);
            if (newCert is SignCertificateResponse.Success success)
            {
                ctx.Response.StatusCode = (int)HttpStatusCode.OK;
                ctx.Response.ContentType = Constants.Pkcs7MimeType;
                await using var writer = new StreamWriter(ctx.Response.Body);
                var certCollection = new X509Certificate2Collection(success.Certificate);
                var certBytes = certCollection.Export(X509ContentType.Pkcs7);
                success.Certificate.Dispose();
                var base64String = Convert.ToBase64String(certBytes!, Base64FormattingOptions.InsertLineBreaks);
                await writer.WriteLineAsync(Constants.BeginPkcs7).ConfigureAwait(false);
                await writer.WriteLineAsync(base64String).ConfigureAwait(false);
                await writer.WriteAsync(Constants.EndPkcs7).ConfigureAwait(false);
                await writer.FlushAsync().ConfigureAwait(false);
            }
            else
            {
                var error = (SignCertificateResponse.Error)newCert;
                ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                ctx.Response.ContentType = Constants.TextPlainMimeType;
                await using var writer = new StreamWriter(ctx.Response.Body);
                foreach (var line in error.Errors)
                {
                    await writer.WriteLineAsync(line).ConfigureAwait(false);
                }

                await writer.FlushAsync().ConfigureAwait(false);
            }
        }
    }
}