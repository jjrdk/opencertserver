namespace OpenCertServer.Ca.Server.Handlers;

using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;

public static class CertificateRetrievalHandler
{
    private static readonly ReadOnlyMemory<byte> NewLine = new[] { (byte)'\n' };

    public static async Task HandleGet(HttpContext context)
    {
        var store = context.RequestServices.GetRequiredService<IStoreCertificates>();
        var thumbprints = context.Request.Query["thumbprint"];
        var ids = context.Request.Query["id"];
        var thumbCerts = store.GetCertificatesByThumbprint(
            thumbprints.Where(s => s != null)
                .Select(tp => tp.AsMemory()));
        var idCerts = store.GetCertificatesById(ids.Where(s => s != null)
            .Select(tp => new ReadOnlyMemory<byte>(Convert.FromHexString(tp!))));

        context.Response.ContentType = "application/x-pem-file";
        var bodyWriter = context.Response.BodyWriter;
        await foreach (var cert in thumbCerts.Concat(idCerts))
        {
            var pem = PemEncoding.WriteUtf8("CERTIFICATE"u8, cert.RawData);
            await bodyWriter.WriteAsync(pem);
            await bodyWriter.WriteAsync(NewLine);
        }

        await bodyWriter.FlushAsync();
        await bodyWriter.CompleteAsync();
    }
}
