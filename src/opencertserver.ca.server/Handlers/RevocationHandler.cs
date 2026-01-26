using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Utils;

namespace opencertserver.ca.server.Handlers;

public static class RevocationHandler
{
    public static async Task Handle(HttpContext context)
    {
        var clientCert = await context.Connection.GetClientCertificateAsync();
        if (clientCert == null)
        {
            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            await context.Response.CompleteAsync();
            return;
        }
        var signature = context.Request.Query["signature"].ToString().Base64DecodeBytes();
        var serialNumberHex = context.Request.Query["sn"].ToString();
        var asymmetricAlgorithm = clientCert!.GetRSAPublicKey() ?? (AsymmetricAlgorithm?)clientCert.GetECDsaPublicKey();
        var reasonString = context.Request.Query["reason"];
        if (asymmetricAlgorithm == null
         || !asymmetricAlgorithm.VerifySignature(
                Encoding.UTF8.GetBytes(serialNumberHex + reasonString),
                signature,
                HashAlgorithmName.SHA256))
        {
            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            await context.Response.CompleteAsync();
            return;
        }

        if (string.IsNullOrEmpty(serialNumberHex)
         || !Enum.TryParse(reasonString.ToString(), true,
                out X509RevocationReason reason))
        {
            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            await context.Response.CompleteAsync();
            return;
        }

        var ca = context.RequestServices.GetRequiredService<ICertificateAuthority>();
        var result = await ca.RevokeCertificate(serialNumberHex, reason);
        context.Response.StatusCode = result ? (int)HttpStatusCode.OK : (int)HttpStatusCode.NotFound;
        await context.Response.CompleteAsync();
    }
}
