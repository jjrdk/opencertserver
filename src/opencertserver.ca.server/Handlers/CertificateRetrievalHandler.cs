namespace OpenCertServer.Ca.Server.Handlers;

using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;

public static class CertificateRetrievalHandler
{
    private static readonly ReadOnlyMemory<byte> NewLine = new[] { (byte)'\n' };

    public static async Task HandleGet(HttpContext context)
    {
        CaInstruments.CertRetrievalRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = CaInstruments.ActivitySource.StartActivity(ActivityNames.CertificateRetrieval);
        try
        {
            var store = context.RequestServices.GetRequiredService<IStoreCertificates>();
            var thumbprints = context.Request.Query["thumbprint"];
            var ids = context.Request.Query["id"];
            var thumbCerts = store.GetCertificatesByThumbprint(
                thumbprints.Where(s => s != null)
                    .Select(tp => tp.AsMemory()));
            var idCerts = store.GetCertificatesById(
                context.RequestAborted,
                ids.Where(s => s != null)
                .Select(tp => new ReadOnlyMemory<byte>(Convert.FromHexString(tp!))));

            context.Response.ContentType = "application/x-pem-file";
            var bodyWriter = context.Response.BodyWriter;
            await foreach (var cert in thumbCerts.Concat(idCerts).ConfigureAwait(false))
            {
                var pem = PemEncoding.WriteUtf8("CERTIFICATE"u8, cert.RawData);
                await bodyWriter.WriteAsync(pem).ConfigureAwait(false);
                await bodyWriter.WriteAsync(NewLine).ConfigureAwait(false);
            }

            await bodyWriter.FlushAsync().ConfigureAwait(false);
            await bodyWriter.CompleteAsync().ConfigureAwait(false);
            CaInstruments.CertRetrievalSuccesses.Add(1);
            activity?.SetStatus(ActivityStatusCode.Ok);
        }
        catch (Exception ex)
        {
            CaInstruments.CertRetrievalFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            CaInstruments.CertRetrievalDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
        }
    }
}
