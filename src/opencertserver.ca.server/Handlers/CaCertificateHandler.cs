// This file is licensed under the terms in the README file of OpenCertServer.
// This file is part of OpenCertServer.
//
// CA server — certificate retrieval by serial number.
//
// Serves the certificate record for a single issued certificate over
// GET /ca/certificate/{serialNumber} (and POST on the same route). The response body is the certificate in
// PEM form; a serial number that was never issued yields a 404.
namespace OpenCertServer.Ca.Server.Handlers;

using System.Diagnostics;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// Handles retrieval of an issued certificate by its serial number.
/// </summary>
public static class CaCertificateHandler
{
    public static async Task Handle(HttpContext context)
    {
        CaInstruments.CertRetrievalRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = CaInstruments.ActivitySource.StartActivity(ActivityNames.CertificateRetrieval);
        try
        {
            var serialHex = context.Request.RouteValues["serialNumber"]?.ToString();
            if (string.IsNullOrEmpty(serialHex))
            {
                CaInstruments.CertRetrievalFailures.Add(1);
                activity?.SetStatus(ActivityStatusCode.Error, "Missing serial number");
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.CompleteAsync().ConfigureAwait(false);
                return;
            }

            var store = context.RequestServices.GetService<IStoreCertificates>()
                ?? throw new InvalidOperationException(
                    "No certificate store is registered; the certificate cannot be retrieved.");

            // The serial number is hexadecimal when it decodes as such; otherwise it is treated literally.
            var serialBytes = ConvertSerial(serialHex);

            var certificate = await store
                .GetCertificatesById(context.RequestAborted, [serialBytes.AsMemory()])
                .FirstOrDefaultAsync(context.RequestAborted)
                .ConfigureAwait(false);

            if (certificate == null)
            {
                CaInstruments.CertRetrievalFailures.Add(1);
                activity?.SetStatus(ActivityStatusCode.Error, "Certificate not found");
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                await context.Response.CompleteAsync().ConfigureAwait(false);
                return;
            }

            context.Response.ContentType = "application/pem-certificate";
            await context.Response.WriteAsync(certificate.ExportCertificatePem(), context.RequestAborted).ConfigureAwait(false);
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
            var elapsed = Stopwatch.GetElapsedTime(sw).TotalSeconds;
            CaInstruments.CertRetrievalDuration.Record(elapsed);
        }
    }

    /// <summary>
    /// Parses a serial number as hexadecimal when it is valid hex, otherwise as UTF-8 text.
    /// </summary>
    private static byte[] ConvertSerial(string serialHex)
    {
        try
        {
            return Convert.FromHexString(serialHex);
        }
        catch
        {
            return Encoding.UTF8.GetBytes(serialHex);
        }
    }
}
