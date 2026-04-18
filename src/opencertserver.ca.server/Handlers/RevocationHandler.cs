namespace OpenCertServer.Ca.Server.Handlers;

using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;

public static class RevocationHandler
{
    public static async Task Handle(HttpContext context)
    {
        CaInstruments.RevocationRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = CaInstruments.ActivitySource.StartActivity(ActivityNames.Revoke);
        try
        {
            var clientCert = await context.Connection.GetClientCertificateAsync().ConfigureAwait(false);
            if (clientCert == null)
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                await context.Response.CompleteAsync().ConfigureAwait(false);
                CaInstruments.RevocationFailures.Add(1);
                activity?.SetStatus(ActivityStatusCode.Error, "No client certificate");
                CaInstruments.RevocationDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
                return;
            }

            var signature = context.Request.Query["signature"].ToString().Base64DecodeBytes();
            var serialNumberHex = context.Request.Query["sn"].ToString();
            var asymmetricAlgorithm = clientCert.GetRSAPublicKey() ?? (AsymmetricAlgorithm?)clientCert.GetECDsaPublicKey();
            var reasonString = context.Request.Query["reason"];
            if (asymmetricAlgorithm == null
             || !asymmetricAlgorithm.VerifySignature(
                    Encoding.UTF8.GetBytes(serialNumberHex + reasonString),
                    signature,
                    HashAlgorithmName.SHA256))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                await context.Response.CompleteAsync().ConfigureAwait(false);
                CaInstruments.RevocationFailures.Add(1);
                activity?.SetStatus(ActivityStatusCode.Error, "Signature verification failed");
                CaInstruments.RevocationDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
                return;
            }

            if (string.IsNullOrEmpty(serialNumberHex)
             || !Enum.TryParse(reasonString.ToString(), true, out X509RevocationReason reason))
            {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                await context.Response.CompleteAsync().ConfigureAwait(false);
                CaInstruments.RevocationFailures.Add(1);
                activity?.SetStatus(ActivityStatusCode.Error, "Invalid parameters");
                CaInstruments.RevocationDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
                return;
            }

            var ca = context.RequestServices.GetRequiredService<ICertificateAuthority>();
            var result = await ca.RevokeCertificate(serialNumberHex, reason).ConfigureAwait(false);
            context.Response.StatusCode = result ? (int)HttpStatusCode.OK : (int)HttpStatusCode.NotFound;
            await context.Response.CompleteAsync().ConfigureAwait(false);

            if (result)
            {
                CaInstruments.RevocationSuccesses.Add(1);
                activity?.SetStatus(ActivityStatusCode.Ok);
            }
            else
            {
                CaInstruments.RevocationFailures.Add(1);
                activity?.SetStatus(ActivityStatusCode.Error, "Certificate not found");
            }
        }
        catch (Exception ex)
        {
            CaInstruments.RevocationFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            CaInstruments.RevocationDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
        }
    }
}
