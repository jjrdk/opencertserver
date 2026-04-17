using OpenCertServer.Est.Server.Response;

namespace OpenCertServer.Est.Server.Handlers;

using System.Formats.Asn1;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Pkcs7;
using OpenCertServer.Ca.Utils.X509Extensions;

internal static class SimpleEnrollHandler
{
    public static Task<IResult> Handle(
        ClaimsPrincipal? user,
        HttpRequest httpRequest,
        ICertificateAuthority certificateAuthority,
        IManualAuthorizationStrategy manualAuthorizationStrategy,
        CancellationToken cancellationToken)
    {
        return HandleProfile("", certificateAuthority, httpRequest, user, manualAuthorizationStrategy,
            cancellationToken);
    }

    public static async Task<IResult> HandleProfile(
        [FromRoute] string profileName,
        ICertificateAuthority certificateAuthority,
        HttpRequest httpRequest,
        ClaimsPrincipal? user,
        IManualAuthorizationStrategy manualAuthorizationStrategy,
        CancellationToken cancellationToken)
    {
        var body = httpRequest.Body;
        var responseType = httpRequest.GetTypedHeaders().Accept;
        using var reader = new StreamReader(body, Encoding.UTF8);
        var requestContent = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            requestContent = requestContent.NormalizeBase64();
        }
        catch (FormatException)
        {
        }
        catch (InvalidOperationException o)
        {
            return Results.Text(o.Message, Constants.TextPlainMimeType, Encoding.UTF8,
                (int)HttpStatusCode.BadRequest);
        }

        if (!requestContent.TryVerifyTlsUniqueValue(out var proofOfPossessionError))
        {
            return Results.Text(proofOfPossessionError, Constants.TextPlainMimeType, Encoding.UTF8,
                (int)HttpStatusCode.BadRequest);
        }

        var csrDer = Convert.FromBase64String(requestContent);
        var csr = CertificateRequest.LoadSigningRequest(
                csrDer,
                HashAlgorithmName.SHA256,
                signerSignaturePadding: RSASignaturePadding.Pss);

        if (manualAuthorizationStrategy.TryGetPendingAuthorization(
            httpRequest,
            user,
            csr,
            out var retryAfter,
            out var pendingMessage))
        {
            return new RetryAfterResult(retryAfter, pendingMessage);
        }

        SignCertificateResponse newCert;
        try
        {
            newCert = await certificateAuthority.SignCertificateRequest(
                csr,
                profileName,
                user?.Identity as ClaimsIdentity,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return Results.Text($"The enrollment CSR could not be parsed: {ex.Message}", Constants.TextPlainMimeType,
                Encoding.UTF8,
                (int)HttpStatusCode.BadRequest);
        }

        if (newCert is SignCertificateResponse.Success success)
        {
            // This is a deviation from the RFC but is easier to parse.
            if (responseType.Any(x =>
                x.MediaType.HasValue &&
                x.MediaType.Value.Equals(Constants.PemFile, StringComparison.OrdinalIgnoreCase)))
            {
                return Results.Text(success.Certificate.ToPemChain(success.Issuers), Constants.PemFile);
            }

            X509Certificate2[] content = [success.Certificate];
            var signedResponse = new SignedData(version: 1, certificates: content);
            var contentInfo = new CmsContentInfo(
                Oids.Pkcs7Signed.InitializeOid(Oids.Pkcs7SignedFriendlyName),
                signedResponse);
            var writer = new AsnWriter(AsnEncodingRules.DER);
            contentInfo.Encode(writer);
            var contentBytes = writer.Encode();
            return Results.Text(Convert.ToBase64String(contentBytes), Constants.PkiMimeTypeCertsOnly);
        }

        var error = (SignCertificateResponse.Error)newCert;
        return Results.Text(string.Join(Environment.NewLine, error.Errors), Constants.TextPlainMimeType, Encoding.UTF8,
            (int)HttpStatusCode.BadRequest);
    }
}
