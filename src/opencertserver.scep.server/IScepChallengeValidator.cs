namespace OpenCertServer.Scep.Server;

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// What a challenge validator gets to decide on: the SCEP transaction, the
/// challenge password from the request and the request itself.
/// </summary>
/// <param name="TransactionId">The SCEP <c>transactionID</c>.</param>
/// <param name="ChallengePassword">The PKCS#9 challenge password from the CSR, if any.</param>
/// <param name="Request">The decrypted PKCS#10 request.</param>
/// <param name="RequestDer">The DER encoding of <paramref name="Request"/>, as sent.</param>
/// <param name="ProfileName">The CA profile the request will be issued from.</param>
/// <param name="MessageType">Initial enrollment or renewal.</param>
public sealed record ScepChallengeContext(
    string TransactionId,
    string? ChallengePassword,
    CertificateRequest Request,
    byte[] RequestDer,
    string? ProfileName,
    ScepMessageType MessageType);

/// <summary>
/// The outcome of a challenge validation.
/// </summary>
/// <param name="Allowed">Whether a certificate may be issued.</param>
/// <param name="Requestor">Optional identity to pass to the CA as the requestor.</param>
/// <param name="Reason">Why the request was denied, for logging - never sent to the client.</param>
public sealed record ScepChallengeResult(bool Allowed, ClaimsIdentity? Requestor = null, string? Reason = null)
{
    /// <summary>An allowed result without a requestor identity.</summary>
    public static ScepChallengeResult Allow() => new(true);

    /// <summary>A denied result.</summary>
    public static ScepChallengeResult Deny(string reason) => new(false, Reason: reason);
}

/// <summary>
/// Decides whether a SCEP enrollment may proceed. The default implementation compares a
/// shared secret; an Intune implementation asks the Intune SCEP validation service.
/// </summary>
public interface IScepChallengeValidator
{
    /// <summary>Validates the challenge of a request.</summary>
    Task<ScepChallengeResult> Validate(ScepChallengeContext context, CancellationToken cancellationToken);

    /// <summary>Called after a certificate has been issued for the request.</summary>
    Task NotifySuccess(ScepChallengeContext context, X509Certificate2 issued, CancellationToken cancellationToken);

    /// <summary>Called when issuing failed after the challenge was accepted, or was denied.</summary>
    Task NotifyFailure(ScepChallengeContext context, string reason, CancellationToken cancellationToken);
}
