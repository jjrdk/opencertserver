﻿namespace OpenCertServer.Est.Server.Handlers
{
    using System;
    using System.IO;
    using System.Net;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Ca.Utils;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Primitives;
    using OpenCertServer.Ca;

    internal sealed class SimpleReEnrollHandler
    {
        private readonly ICertificateAuthority _certificateAuthority;

        public SimpleReEnrollHandler(ICertificateAuthority certificateAuthority)
        {
            _certificateAuthority = certificateAuthority;
        }

        public async Task Handle(HttpContext ctx)
        {
            var cert = ctx.Request.HttpContext.Connection.ClientCertificate;

            if (cert == null)
            {
                X509Certificate2? ReadCertHeader(StringValues stringValues)
                {
                    Span<byte> bytes = stackalloc byte[stringValues[0].Length];
                    if (Convert.TryFromBase64String(stringValues, bytes, out var read))
                    {
                        cert = new X509Certificate2(bytes[..read]);
                    }

                    return cert;
                }

                var certHeader = ctx.Request.Headers["X-Client-Cert"];
                if (certHeader.Count > 0 && !string.IsNullOrWhiteSpace(certHeader[0]))
                {
                    cert = ReadCertHeader(certHeader);
                }
            }

            if (cert == null)
            {
                ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                return;
            }

            var request = cert.PublicKey.Oid.Value switch
            {
                CertificateConstants.EcdsaOid => new CertificateRequest(
                    cert.SubjectName,
                    cert.GetECDsaPublicKey()!,
                    HashAlgorithmName.SHA256),
                CertificateConstants.RsaOid => new CertificateRequest(
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

            var newCert = _certificateAuthority.SignCertificateRequest(request);
            if (newCert is not SignCertificateResponse.Success success)
            {
                ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                return;
            }

            var value = new X509Certificate2Collection(success.Certificate).Export(X509ContentType.Pkcs7);
            cert.Dispose();

            ctx.Response.StatusCode = (int)HttpStatusCode.OK;
            ctx.Response.ContentType = Constants.Pkcs7MimeType;
            await using var writer = new StreamWriter(ctx.Response.Body);

            var base64String = Convert.ToBase64String(value!, Base64FormattingOptions.InsertLineBreaks);
            await writer.WriteLineAsync(Constants.BeginPkcs7).ConfigureAwait(false);
            await writer.WriteLineAsync(base64String).ConfigureAwait(false);
            await writer.WriteAsync(Constants.EndPkcs7).ConfigureAwait(false);
            await writer.FlushAsync().ConfigureAwait(false);
        }
    }
}