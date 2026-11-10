namespace OpenCertServer.Scep.Server;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// The validator in place when the host has not configured one: it refuses every request.
/// A SCEP endpoint without a challenge check would issue to anyone who can reach it, so an
/// unconfigured endpoint answers GetCACaps and GetCACert, but issues nothing.
/// </summary>
public sealed class NotConfiguredChallengeValidator : IScepChallengeValidator
{
    /// <inheritdoc />
    public Task<ScepChallengeResult> Validate(ScepChallengeContext context, CancellationToken cancellationToken) =>
        Task.FromResult(ScepChallengeResult.Deny("No SCEP challenge validator is configured."));

    /// <inheritdoc />
    public Task NotifySuccess(ScepChallengeContext context, X509Certificate2 issued, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    /// <inheritdoc />
    public Task NotifyFailure(ScepChallengeContext context, string reason, CancellationToken cancellationToken) =>
        Task.CompletedTask;
}
