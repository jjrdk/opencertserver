namespace OpenCertServer.Scep.Server;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

/// <summary>
/// Accepts a request when its challenge password equals a configured shared secret.
/// The comparison runs in constant time.
/// </summary>
public sealed class SharedSecretChallengeValidator : IScepChallengeValidator
{
    private readonly byte[] _secret;

    /// <summary>Creates a validator for the given shared secret.</summary>
    public SharedSecretChallengeValidator(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        _secret = Encoding.UTF8.GetBytes(secret);
    }

    /// <inheritdoc />
    public Task<ScepChallengeResult> Validate(ScepChallengeContext context, CancellationToken cancellationToken)
    {
        // A renewal proves itself with the previous certificate, which the handler has
        // verified; RFC 8894 does not require a challenge password for it.
        if (context.MessageType == ScepMessageType.RenewalReq && context.PreviousCertificate is not null)
        {
            return Task.FromResult(ScepChallengeResult.Allow());
        }

        if (context.ChallengePassword is null)
        {
            return Task.FromResult(ScepChallengeResult.Deny("The request carries no challenge password."));
        }

        var given = Encoding.UTF8.GetBytes(context.ChallengePassword);
        return Task.FromResult(CryptographicOperations.FixedTimeEquals(given, _secret)
            ? ScepChallengeResult.Allow()
            : ScepChallengeResult.Deny("The challenge password does not match."));
    }

    /// <inheritdoc />
    public Task NotifySuccess(ScepChallengeContext context, X509Certificate2 issued, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    /// <inheritdoc />
    public Task NotifyFailure(ScepChallengeContext context, string reason, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
