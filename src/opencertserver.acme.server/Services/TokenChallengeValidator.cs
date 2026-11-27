using CertesSlim.Acme;
using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Services;

public abstract class TokenChallengeValidator : IValidateChallenges
{
    /// <summary>
    /// The ACME challenge type this concrete token validator handles. Subclasses override it to declare
    /// their type (e.g. <c>http-01</c>, <c>dns-01</c>) so the factory can route by <see cref="Challenge.Type"/>.
    /// </summary>
    public abstract string AppliesTo { get; }

    protected abstract Task<(List<string>? Contents, AcmeError? Error)> LoadChallengeResponse(
        Challenge challenge,
        string? accountUri,
        CancellationToken cancellationToken);

    protected abstract string GetExpectedContent(Challenge challenge, Account account);

    public virtual async Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
        Challenge challenge,
        Account account,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(challenge);

        ArgumentNullException.ThrowIfNull(account);

        if (account.Status != AccountStatus.Valid)
        {
            return (
                false,
                new AcmeError
                {
                    Type = "unauthorized",
                    Detail = "Account invalid",
                    Identifier = challenge.Authorization.Identifier
                });
        }

        if (challenge.Authorization.Expires < DateTimeOffset.UtcNow)
        {
            challenge.Authorization.SetStatus(AuthorizationStatus.Expired);
            return (false,
                    new AcmeError
                    {
                        Type = "unauthorized",
                        Detail = "Authorization expired",
                        Identifier = challenge.Authorization.Identifier
                    });
        }

        if (challenge.Authorization.Order.Expires < DateTimeOffset.UtcNow)
        {
            challenge.Authorization.Order.SetStatus(OrderStatus.Invalid);
            return (false, new AcmeError { Type = "malformed", Detail = "Order expired" });
        }

        var (challengeContent, error) = await LoadChallengeResponse(challenge, account.AccountUri, cancellationToken)
            .ConfigureAwait(false);
        if (error != null)
        {
            return (false, error);
        }

        var expectedResponse = GetExpectedContent(challenge, account);
        return challengeContent?.Contains(expectedResponse) != true
            ? (false,
               new AcmeError
               {
                   Type = "incorrectResponse",
                   Detail = "Challenge response did not contain the expected content.",
                   Identifier = challenge.Authorization.Identifier
               })
            : (true, null);
    }
}
