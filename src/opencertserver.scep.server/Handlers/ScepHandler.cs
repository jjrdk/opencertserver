namespace OpenCertServer.Scep.Server.Handlers;

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// The SCEP endpoint (RFC 8894, section 4): one path, the operation in the query.
/// </summary>
internal static class ScepHandler
{
    private const string PkiMessage = "application/x-pki-message";
    private const string CaRaCert = "application/x-x509-ca-ra-cert";

    // RFC 8894, 3.5.2.
    private const string Capabilities = "POSTPKIOperation\nSHA-256\nAES\nSCEPStandard\nRenewal\n";

    public static Task<IResult> Get(
        HttpContext context,
        ScepServerOptions options,
        ICertificateAuthority ca,
        IScepChallengeValidator validator,
        ScepTransactionIds transactions,
        ILoggerFactory loggers,
        CancellationToken cancellationToken) =>
        Dispatch(context, null, options, ca, validator, transactions, loggers, cancellationToken);

    public static Task<IResult> GetProfile(
        string profileName,
        HttpContext context,
        ScepServerOptions options,
        ICertificateAuthority ca,
        IScepChallengeValidator validator,
        ScepTransactionIds transactions,
        ILoggerFactory loggers,
        CancellationToken cancellationToken) =>
        Dispatch(context, profileName, options, ca, validator, transactions, loggers, cancellationToken);

    private static async Task<IResult> Dispatch(
        HttpContext context,
        string? profileName,
        ScepServerOptions options,
        ICertificateAuthority ca,
        IScepChallengeValidator validator,
        ScepTransactionIds transactions,
        ILoggerFactory loggers,
        CancellationToken cancellationToken)
    {
        var operation = context.Request.Query["operation"].ToString();
        var profile = profileName ?? options.DefaultProfile;
        return operation switch
        {
            "GetCACaps" => Results.Text(Capabilities, "text/plain"),
            "GetCACert" => await GetCaCert(profile, options, ca, cancellationToken).ConfigureAwait(false),
            "PKIOperation" => await PkiOperation(context, profile, options, ca, validator, transactions,
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
        // A separate RA: the RA certificate first, then the published CA chain - the same set as
        // EST /cacerts. Below a root that is the issuing CA plus the root; Windows looks for the
        // root thumbprint of its Intune profile here and gives up before the request without it.
        var chain = await ca.GetPublishedCertificates(profile, cancellationToken).ConfigureAwait(false);
        X509Certificate2[] certificates = [options.RaCertificate, .. chain];
        return Results.Bytes(ScepMessageCodec.EncodeCertificatesOnly(certificates), CaRaCert);
    }

    private static async Task<IResult> PkiOperation(
        HttpContext context,
        string? profile,
        ScepServerOptions options,
        ICertificateAuthority ca,
        IScepChallengeValidator validator,
        ScepTransactionIds transactions,
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

        if (request.MessageType is not (ScepMessageType.PkcsReq or ScepMessageType.RenewalReq)
            || request.CsrDer is null)
        {
            return Failure(request, ScepFailInfo.BadRequest, options);
        }

        // A transaction ID is accepted once per window: a captured request, replayed,
        // would otherwise have the CA issue again.
        if (!transactions.TryClaim(request.TransactionId))
        {
            logger.LogWarning("SCEP transaction {TransactionId} refused: transaction ID already used",
                request.TransactionId);
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

        X509Certificate2? previous = null;
        if (request.MessageType == ScepMessageType.RenewalReq)
        {
            var refusal = await CheckRenewal(request.SignerCertificate, csr, profile, ca, cancellationToken)
                .ConfigureAwait(false);
            if (refusal is not null)
            {
                logger.LogInformation("SCEP transaction {TransactionId}: renewal refused: {Reason}",
                    request.TransactionId, refusal);
                return Failure(request, ScepFailInfo.BadRequest, options);
            }

            previous = request.SignerCertificate;
        }

        var challenge = new ScepChallengeContext(
            request.TransactionId,
            ReadChallengePassword(csr),
            csr,
            request.CsrDer,
            profile,
            request.MessageType,
            previous);

        var decision = await validator.Validate(challenge, cancellationToken).ConfigureAwait(false);
        if (!decision.Allowed)
        {
            logger.LogInformation("SCEP transaction {TransactionId} denied: {Reason}",
                request.TransactionId, decision.Reason);
            await validator.NotifyFailure(challenge, decision.Reason ?? "denied", cancellationToken)
                .ConfigureAwait(false);
            return Failure(request, ScepFailInfo.BadRequest, options);
        }

        // For a renewal the CA supersedes the previous certificate once the new one is issued.
        var response = await ca.SignCertificateRequest(
                csr, profile, decision.Requestor, previous, cancellationToken: cancellationToken)
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

    /// <summary>
    /// A RenewalReq is signed with the certificate it renews (RFC 8894, 3.3.1.2). That
    /// certificate is the proof, so it is checked cryptographically here: it must chain to
    /// this profile's CA, be valid now, not be revoked, and carry the same subject and the
    /// same subjectAltName as the request - as EST requires for simplereenroll (RFC 7030,
    /// 4.2.2); the profile copies the subjectAltName from the request. The CA core compares
    /// only the issuer name of <c>reenrollingFrom</c>, which a self-signed certificate can
    /// imitate (#96). Returns the reason for a refusal, or null.
    /// </summary>
    private static async Task<string?> CheckRenewal(
        X509Certificate2 previous,
        CertificateRequest csr,
        string? profile,
        ICertificateAuthority ca,
        CancellationToken cancellationToken)
    {
        var roots = await ca.GetRootCertificates(profile, cancellationToken).ConfigureAwait(false);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.ExtraStore.AddRange(roots);
        // Revocation is checked against this CA's own list below, not over the network.
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        if (!chain.Build(previous))
        {
            return "the signing certificate is not a valid certificate of this CA: "
                + string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()));
        }

        var crl = await ca.GetRevocationList(profile, cancellationToken).ConfigureAwait(false);
        var revoked = CertificateRevocationListBuilder.Load(crl, out _);
        if (revoked.RemoveEntry(Convert.FromHexString(previous.GetSerialNumberString())))
        {
            return "the signing certificate is revoked";
        }

        if (!csr.SubjectName.RawData.AsSpan().SequenceEqual(previous.SubjectName.RawData))
        {
            return "the request names a different subject than the certificate it renews";
        }

        if (!SubjectAltNames(previous.Extensions).SetEquals(SubjectAltNames(csr.CertificateExtensions)))
        {
            return "the request names a different subjectAltName than the certificate it renews";
        }

        return null;
    }

    // Compared by content: a set of byte arrays would compare references.
    private static HashSet<string> SubjectAltNames(IEnumerable<X509Extension> extensions) =>
        extensions.Where(x => x.Oid?.Value == Oids.SubjectAltName)
            .Select(x => Convert.ToHexString(x.RawData))
            .ToHashSet(StringComparer.Ordinal);

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
