namespace OpenCertServer.Contrib.Intune;

using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using OpenCertServer.Scep.Server;

/// <summary>
/// Lets Intune decide. Every PKCSReq carries a challenge Intune handed to the device;
/// the CSR as a whole is sent to Intune's validation service, which checks challenge,
/// subject and SANs against the SCEP profile. Intune unreachable, throttled or saying
/// no all mean: deny - nothing is ever issued on a hunch. A renewal signed with the
/// previous certificate passes without Intune, as it does for the shared secret.
/// </summary>
public sealed partial class IntuneChallengeValidator : IScepChallengeValidator
{
    /// <summary>E_FAIL - what the reference policy module reports when the CA refused.</summary>
    private const long CaRefusedHResult = unchecked((int)0x80004005);

    private readonly IIntuneClient _intune;
    private readonly ILogger<IntuneChallengeValidator> _logger;

    // Transactions Intune has allowed and not yet heard the outcome of. Intune is told
    // about a failure only for those: when Intune itself said no, it knows already.
    private readonly ConcurrentDictionary<string, byte> _allowed = new(StringComparer.Ordinal);

    public IntuneChallengeValidator(IIntuneClient intune, ILogger<IntuneChallengeValidator> logger)
    {
        _intune = intune;
        _logger = logger;
    }

    public async Task<ScepChallengeResult> Validate(ScepChallengeContext context, CancellationToken cancellationToken)
    {
        if (context.MessageType == ScepMessageType.RenewalReq && context.PreviousCertificate is not null)
        {
            return ScepChallengeResult.Allow();
        }

        if (context.ChallengePassword is null)
        {
            return ScepChallengeResult.Deny("The request carries no challenge password.");
        }

        try
        {
            await _intune.ValidateRequest(context.TransactionId, Convert.ToBase64String(context.RequestDer), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (IntuneRefusedException ex)
        {
            LogRefused(_logger, context.TransactionId, ex.Code, ex.Description);
            return ScepChallengeResult.Deny(ex.Message);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            LogUnreachable(_logger, ex, context.TransactionId);
            return ScepChallengeResult.Deny("Intune could not be asked: " + ex.Message);
        }

        _allowed[context.TransactionId] = 0;
        var requestor = new ClaimsIdentity("Intune");
        requestor.AddClaim(new Claim("scep:transaction", context.TransactionId));
        return ScepChallengeResult.Allow() with { Requestor = requestor };
    }

    public async Task NotifySuccess(ScepChallengeContext context, X509Certificate2 issued, CancellationToken cancellationToken)
    {
        if (!_allowed.TryRemove(context.TransactionId, out _))
        {
            return;
        }

        try
        {
            await _intune.NotifySuccess(
                    context.TransactionId,
                    Convert.ToBase64String(context.RequestDer),
                    new IntuneIssuedInfo(issued.Thumbprint, issued.SerialNumber, issued.NotAfter.ToUniversalTime(), issued.Issuer),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IntuneRefusedException or HttpRequestException or TaskCanceledException)
        {
            // The certificate is issued and on its way; a lost notification costs Intune
            // its bookkeeping, not the device its certificate.
            LogNotificationLost(_logger, ex, "success", context.TransactionId);
        }
    }

    public async Task NotifyFailure(ScepChallengeContext context, string reason, CancellationToken cancellationToken)
    {
        if (!_allowed.TryRemove(context.TransactionId, out _))
        {
            return;
        }

        try
        {
            await _intune.NotifyFailure(
                    context.TransactionId,
                    Convert.ToBase64String(context.RequestDer),
                    CaRefusedHResult,
                    reason,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IntuneRefusedException or HttpRequestException or TaskCanceledException)
        {
            LogNotificationLost(_logger, ex, "failure", context.TransactionId);
        }
    }

    [LoggerMessage(LogLevel.Information, "SCEP transaction {TransactionId}: Intune refused the challenge: {Code}: {Description}")]
    private static partial void LogRefused(ILogger logger, string transactionId, string code, string description);

    [LoggerMessage(LogLevel.Warning, "SCEP transaction {TransactionId}: Intune could not be asked - the request is denied")]
    private static partial void LogUnreachable(ILogger logger, Exception exception, string transactionId);

    [LoggerMessage(LogLevel.Warning, "SCEP transaction {TransactionId}: the {Kind} notification did not reach Intune")]
    private static partial void LogNotificationLost(ILogger logger, Exception exception, string kind, string transactionId);
}
