namespace OpenCertServer.Ca.Server.Handlers;

using System.Formats.Asn1;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Ca.Utils.X509;

public static class OcspHandler
{
    public static async Task Handle(HttpContext context)
    {
        var cancellationToken = context.RequestAborted;
        var validators = context.RequestServices.GetServices<IValidateOcspRequest>();
        var storeCertificates = context.RequestServices.GetRequiredService<IStoreCertificates>();
        var responderId = context.RequestServices.GetRequiredService<IResponderId>();
        OcspResponse ocspResponse;
        try
        {
            var buffer = new MemoryStream();
            await context.Request.Body.CopyToAsync(buffer, cancellationToken);
            buffer.Seek(0, SeekOrigin.Begin);
            var request = new OcspRequest(new AsnReader(buffer.ToArray(), AsnEncodingRules.DER));
            var results = await Task.WhenAll(validators.Select(v => v.Validate(request)));
            var error = string.Join("\n", results.Where(x => !string.IsNullOrEmpty(x)));
            if (!string.IsNullOrEmpty(error))
            {
                ocspResponse = new OcspResponse(OcspResponseStatus.MalformedRequest);
            }
            else
            {
                var searchResults = await Task.WhenAll(
                    request.TbsRequest.RequestList.Select(r =>
                        storeCertificates.GetCertificateStatus(r.CertIdentifier)));
                ocspResponse = new OcspResponse(
                    OcspResponseStatus.Successful,
                    new OcspBasicResponse(
                        new ResponseData(
                            TypeVersion.V1,
                            responderId,
                            DateTimeOffset.UtcNow,
                            searchResults.Select(r =>
                                new SingleResponse(r.Item1, (r.Item2, r.Item3), DateTimeOffset.UtcNow))),
                        new AlgorithmIdentifier(Oids.EcPublicKey.InitializeOid(), Oids.secp521r1.InitializeOid()), []));
            }
        }
        catch (Exception)
        {
            ocspResponse = new OcspResponse(OcspResponseStatus.InternalError);
        }

        var writer = new AsnWriter(AsnEncodingRules.DER);
        ocspResponse.Encode(writer);
        var errorBytes = writer.Encode();
        var response = context.Response;
        response.ContentType = "application/ocsp-response";
        await response.Body.WriteAsync(errorBytes, cancellationToken);
        await response.CompleteAsync();
    }
}
