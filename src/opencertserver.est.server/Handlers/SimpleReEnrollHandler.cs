using OpenCertServer.Ca.Utils.X509Extensions;

namespace OpenCertServer.Est.Server.Handlers;

using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Ca.Utils;
using Microsoft.AspNetCore.Http;
using Ca;

internal sealed class SimpleReEnrollHandler
{
    private readonly ICertificateAuthority _certificateAuthority;

    public SimpleReEnrollHandler(ICertificateAuthority certificateAuthority)
    {
        _certificateAuthority = certificateAuthority;
    }

    public async Task Handle(HttpContext ctx)
    {
        var cert = await ctx.Request.HttpContext.Connection.GetClientCertificateAsync();

        if (cert == null)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            return;
        }

        var request = cert.PublicKey.Oid.Value switch
        {
            Oids.EcPublicKey => new CertificateRequest(
                cert.SubjectName,
                cert.GetECDsaPublicKey()!,
                HashAlgorithmName.SHA256),
            Oids.Rsa => new CertificateRequest(
                cert.SubjectName,
                cert.GetRSAPublicKey()!,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss),
            _ => null
        };
        if (request == null)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            return;
        }

        foreach (var extension in cert.Extensions)
        {
            request.CertificateExtensions.Add(extension);
        }

        var newCert = _certificateAuthority.SignCertificateRequest(request, cert);
        if (newCert is not SignCertificateResponse.Success success)
        {
            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            return;
        }

        var pem = success.Certificate.ToPemChain(success.Issuers);

        ctx.Response.StatusCode = (int)HttpStatusCode.OK;
        ctx.Response.ContentType = Constants.PemMimeType;
        await using var writer = new StreamWriter(ctx.Response.Body);

        await writer.WriteLineAsync(pem).ConfigureAwait(false);
        await writer.FlushAsync().ConfigureAwait(false);
        await _certificateAuthority.RevokeCertificate(cert.GetSerialNumberString(), X509RevocationReason.Superseded);
    }
}
