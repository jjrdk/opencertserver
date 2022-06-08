namespace OpenCertServer.Acme.Server.Services
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using Abstractions.Model;
    using Abstractions.Services;

    public abstract class TokenChallengeValidator : IValidateChallenges
    {
        protected abstract Task<(List<string>? Contents, AcmeError? Error)> LoadChallengeResponse(
            Challenge challenge,
            CancellationToken cancellationToken);

        protected abstract string GetExpectedContent(Challenge challenge, Account account);

        public virtual async Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            Challenge challenge,
            Account account,
            CancellationToken cancellationToken)
        {
            if (challenge is null)
            {
                throw new ArgumentNullException(nameof(challenge));
            }

            if (account is null)
            {
                throw new ArgumentNullException(nameof(account));
            }

            if (account.Status != AccountStatus.Valid)
            {
                return (false, new AcmeError("unauthorized", "Account invalid", challenge.Authorization.Identifier));
            }

            if (challenge.Authorization.Expires < DateTimeOffset.UtcNow)
            {
                challenge.Authorization.SetStatus(AuthorizationStatus.Expired);
                return (false,
                    new AcmeError("custom:authExpired", "Authorization expired", challenge.Authorization.Identifier));
            }

            if (challenge.Authorization.Order.Expires < DateTimeOffset.UtcNow)
            {
                challenge.Authorization.Order.SetStatus(OrderStatus.Invalid);
                return (false, new AcmeError("custom:orderExpired", "Order expired"));
            }

            var (challengeContent, error) = await LoadChallengeResponse(challenge, cancellationToken);
            if (error != null)
            {
                return (false, error);
            }

            var expectedResponse = GetExpectedContent(challenge, account);
            return challengeContent?.Contains(expectedResponse) != true
                ? (false,
                    new AcmeError(
                        "incorrectResponse",
                        "Challenge response dod not contain the expected content.",
                        challenge.Authorization.Identifier))
                : (true, null);
        }
    }
}
