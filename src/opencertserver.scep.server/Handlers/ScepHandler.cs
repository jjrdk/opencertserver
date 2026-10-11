namespace OpenCertServer.Scep.Server.Handlers;

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// The SCEP endpoint (RFC 8894, section 4): one path, the operation in the query.
/// </summary>
internal static class ScepHandler
{
    private const string PkiMessage = "application/x-pki-message";
    private const string CaRaCert = "application/x-x509-ca-ra-cert";

    // RFC 8894, 3.5.2. Renewal is not offered yet; a client that sees it would
    // send RenewalReq, which this probe answers with badRequest.
    private const string Capabilities = "POSTPKIOperation\nSHA-256\nAES\nSCEPStandard\n";

    public static Task<IResult> Get(
        HttpContext context,
        ScepServerOptions options,
        ICertificateAuthority ca,
        IScepChallengeValidator validator,
        ILoggerFactory loggers,
        CancellationToken cancellationToken) =>
        Dispatch(context, null, options, ca, validator, loggers, cancellationToken);

    public static Task<IResult> GetProfile(
        string profileName,
        HttpContext context,
        ScepServerOptions options,
        ICertificateAuthority ca,
        IScepChallengeValidator validator,
        ILoggerFactory loggers,
        CancellationToken cancellationToken) =>
        Dispatch(context, profileName, options, ca, validator, loggers, cancellationToken);

    private static async Task<IResult> Dispatch(
        HttpContext context,
        string? profileName,
        ScepServerOptions options,
        ICertificateAuthority ca,
        IScepChallengeValidator validator,
        ILoggerFactory loggers,
        CancellationToken cancellationToken)
    {
        var operation = context.Request.Query["operation"].ToString();
        var profile = profileName ?? options.DefaultProfile;
        return operation switch
        {
            "GetCACaps" => Results.Text(Capabilities, "text/plain"),
            "GetCACert" => await GetCaCert(profile, options, ca, cancellationToken).ConfigureAwait(false),
            "PKIOperation" => await PkiOperation(context, profile, options, ca, validator,
                loggers.CreateLogger("OpenCertServer.Scep"), cancellationToken).ConfigureAwait(false),
            _ => Results.BadRequest($"Unsupported operation '{operation}'.")
        };
    }

    private static async Task<IResult> GetCaCert(
        string? profile,
        ScepServerOptions options,
        ICertificateAuthority ca,
        CancellationToken cancellationToken)
    {
        // A separate RA: the RA certificate first, then the CA chain.
        var chain = await ca.GetRootCertificates(profile, cancellationToken).ConfigureAwait(false);
        X509Certificate2[] certificates = [options.RaCertificate, .. chain];
        return Results.Bytes(ScepMessageCodec.EncodeCertificatesOnly(certificates), CaRaCert);
    }

    private static async Task<IResult> PkiOperation(
        HttpContext context,
        string? profile,
        ScepServerOptions options,
        ICertificateAuthority ca,
        IScepChallengeValidator validator,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        byte[] message;
        if (HttpMethods.IsPost(context.Request.Method))
        {
            using var buffer = new MemoryStream();
            await context.Request.Body.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
            message = buffer.ToArray();
        }
        else
        {
            // GET carries the message base64-encoded in the query. A '+' arrives as a
            // space after URL decoding when the client did not escape it.
            var encoded = context.Request.Query["message"].ToString().Replace(' ', '+');
            try
            {
                message = Convert.FromBase64String(encoded);
            }
            catch (FormatException)
            {
                return Results.BadRequest("The message parameter is not valid base64.");
            }
        }

        ScepRequest request;
        try
        {
            request = ScepMessageCodec.Decode(message, options.RaCertificate);
        }
        catch (ScepException ex)
        {
            // Without a verified request there is no recipient to encrypt to and no
            // transaction to answer; RFC 8894 leaves this to an HTTP error.
            logger.LogWarning(ex, "SCEP message rejected: {Reason}", ex.Message);
            return Results.BadRequest(ex.Message);
        }

        if (request.MessageType != ScepMessageType.PkcsReq || request.CsrDer is null)
        {
            return Failure(request, ScepFailInfo.BadRequest, options);
        }

        CertificateRequest csr;
        try
        {
            csr = CertificateRequest.LoadSigningRequest(
                request.CsrDer,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                signerSignaturePadding: RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException ex)
        {
            logger.LogWarning(ex, "SCEP transaction {TransactionId}: unreadable CSR", request.TransactionId);
            return Failure(request, ScepFailInfo.BadMessageCheck, options);
        }

        var challenge = new ScepChallengeContext(
            request.TransactionId,
            ReadChallengePassword(csr),
            csr,
            request.CsrDer,
            profile,
            request.MessageType);

        var decision = await validator.Validate(challenge, cancellationToken).ConfigureAwait(false);
        if (!decision.Allowed)
        {
            logger.LogInformation("SCEP transaction {TransactionId} denied: {Reason}",
                request.TransactionId, decision.Reason);
            await validator.NotifyFailure(challenge, decision.Reason ?? "denied", cancellationToken)
                .ConfigureAwait(false);
            return Failure(request, ScepFailInfo.BadRequest, options);
        }

        var response = await ca.SignCertificateRequest(
                csr, profile, decision.Requestor, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (response is not SignCertificateResponse.Success success)
        {
            var reason = response is SignCertificateResponse.Error error
                ? string.Join("; ", error.Errors)
                : "The CA did not issue a certificate.";
            logger.LogWarning("SCEP transaction {TransactionId}: CA refused: {Reason}", request.TransactionId, reason);
            await validator.NotifyFailure(challenge, reason, cancellationToken).ConfigureAwait(false);
            return Failure(request, ScepFailInfo.BadRequest, options);
        }

        await validator.NotifySuccess(challenge, success.Certificate, cancellationToken).ConfigureAwait(false);
        return Results.Bytes(
            ScepMessageCodec.EncodeSuccess(request, success.Certificate, options.RaCertificate),
            PkiMessage);
    }

    private static IResult Failure(ScepRequest request, ScepFailInfo failInfo, ScepServerOptions options) =>
        Results.Bytes(ScepMessageCodec.EncodeFailure(request, failInfo, options.RaCertificate), PkiMessage);

    private static string? ReadChallengePassword(CertificateRequest csr)
    {
        foreach (var attribute in csr.OtherRequestAttributes)
        {
            if (attribute.Oid?.Value != ScepOids.ChallengePassword)
            {
                continue;
            }

            // The attribute value is a SET OF DirectoryString; .NET hands over the SET.
            try
            {
                var set = new AsnReader(attribute.RawData, AsnEncodingRules.BER);
                if (set.PeekTag().HasSameClassAndValue(Asn1Tag.SetOf))
                {
                    var values = set.ReadSetOf();
                    return ScepMessageCodec.ReadString(values.ReadEncodedValue().ToArray());
                }

                return ScepMessageCodec.ReadString(attribute.RawData);
            }
            catch (AsnContentException)
            {
                return null;
            }
        }

        return null;
    }
}
