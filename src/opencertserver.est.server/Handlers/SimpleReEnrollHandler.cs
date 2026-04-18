namespace OpenCertServer.Est.Server.Handlers;

using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Ca.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Pkcs7;
using OpenCertServer.Ca.Utils.X509Extensions;

internal static class SimpleReEnrollHandler
{
    public static Task<IResult> Handle(
        HttpContext context,
        ClaimsPrincipal user,
        ICertificateAuthority certificateAuthority,
        CancellationToken cancellationToken)
    {
        return HandleProfile(context, user, certificateAuthority, "", cancellationToken);
    }

    public static async Task<IResult> HandleProfile(
        HttpContext context,
        ClaimsPrincipal user,
        ICertificateAuthority certificateAuthority,
        [FromRoute] string profileName,
        CancellationToken cancellationToken)
    {
        EstInstruments.SimpleReEnrollRequests.Add(1);
        var sw = Stopwatch.GetTimestamp();
        using var activity = EstInstruments.ActivitySource.StartActivity(ActivityNames.SimpleReEnroll);
        IResult result;
        try
        {
            result = await Core().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            EstInstruments.SimpleReEnrollFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            EstInstruments.SimpleReEnrollDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
            throw;
        }

        var statusCode = (result as IStatusCodeHttpResult)?.StatusCode ?? 200;
        if (statusCode >= 400)
        {
            EstInstruments.SimpleReEnrollFailures.Add(1);
            activity?.SetStatus(ActivityStatusCode.Error);
        }
        else
        {
            EstInstruments.SimpleReEnrollSuccesses.Add(1);
            activity?.SetStatus(ActivityStatusCode.Ok);
        }

        EstInstruments.SimpleReEnrollDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
        return result;

        async Task<IResult> Core()
        {
            var cert = await context.Connection.GetClientCertificateAsync(cancellationToken).ConfigureAwait(false);
            using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
            var requestBody = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);

            if (cert == null)
            {
                return Results.Text("A client certificate is required for simple re-enrollment.",
                    Constants.TextPlainMimeType, Encoding.UTF8, (int)HttpStatusCode.BadRequest);
            }

            if (!requestBody.TryVerifyTlsUniqueValue(out var proofOfPossessionError))
            {
                return Results.Text(proofOfPossessionError, Constants.TextPlainMimeType, Encoding.UTF8,
                    (int)HttpStatusCode.BadRequest);
            }

            CertificateRequest request;
            try
            {
                request = PemEncoding.TryFind(requestBody, out _)
                    ? CertificateRequest.LoadSigningRequestPem(
                        requestBody,
                        HashAlgorithmName.SHA256,
                        CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                        RSASignaturePadding.Pss)
                    : CertificateRequest.LoadSigningRequest(
                        requestBody.Base64DecodeBytes(),
                        HashAlgorithmName.SHA256,
                        CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                        RSASignaturePadding.Pss);
            }
            catch (Exception ex)
            {
                return Results.Text($"The re-enrollment CSR could not be parsed: {ex.Message}",
                    Constants.TextPlainMimeType, Encoding.UTF8, (int)HttpStatusCode.BadRequest);
            }

            if (!cert.SubjectName.RawData.AsSpan().SequenceEqual(request.SubjectName.RawData))
            {
                return Results.Text("The re-enrollment CSR Subject must match the current certificate Subject.",
                    Constants.TextPlainMimeType, Encoding.UTF8, (int)HttpStatusCode.BadRequest);
            }

            var currentSans = cert.Extensions.Where(x => x.Oid?.Value == Oids.SubjectAltName)
                .Select(x => x.RawData)
                .ToHashSet();
            var requestedSans = request.CertificateExtensions.Where(x => x.Oid?.Value == Oids.SubjectAltName)
                .Select(x => x.RawData)
                .ToHashSet();
            if (!currentSans.SetEquals(requestedSans))
            {
                return Results.Text(
                    "The re-enrollment CSR SubjectAltName extension must match the current certificate SubjectAltName extension.",
                    Constants.TextPlainMimeType,
                    Encoding.UTF8,
                    (int)HttpStatusCode.BadRequest);
            }

            var newCert = await certificateAuthority.SignCertificateRequest(
                request,
                profileName,
                user.Identity as ClaimsIdentity,
                cert,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            if (newCert is not SignCertificateResponse.Success success)
            {
                var error = (SignCertificateResponse.Error)newCert;
                return Results.Text(string.Join(Environment.NewLine, error.Errors), Constants.TextPlainMimeType,
                    Encoding.UTF8, (int)HttpStatusCode.BadRequest);
            }

            var responseType = context.Request.GetTypedHeaders().Accept;
            // This is a deviation from the RFC but is easier to parse.
            if (responseType.Any(x =>
                x.MediaType.HasValue &&
                x.MediaType.Value.Equals(Constants.PemFile, StringComparison.OrdinalIgnoreCase)))
            {
                return Results.Text(success.Certificate.ToPemChain(success.Issuers), Constants.PemFile);
            }

            X509Certificate2[] content = [success.Certificate, ..success.Issuers];
            var signedResponse = new SignedData(version: 1, certificates: content);
            var contentInfo = new CmsContentInfo(
                Oids.Pkcs7Signed.InitializeOid(Oids.Pkcs7SignedFriendlyName),
                signedResponse);
            var writer = new AsnWriter(AsnEncodingRules.DER);
            contentInfo.Encode(writer);
            var contentBytes = writer.Encode();
            return Results.Text(Convert.ToBase64String(contentBytes), Constants.PkiMimeTypeCertsOnly);
        }
    }
}
