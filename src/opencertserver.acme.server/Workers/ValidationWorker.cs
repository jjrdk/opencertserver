using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Server.Workers;

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Services;
using Abstractions.Storage;
using Abstractions.Workers;

public sealed class ValidationWorker : IValidationWorker
{
    private readonly IStoreOrders _orderStore;
    private readonly IStoreAccounts _accountStore;
    private readonly IChallengeValidatorFactory _challengeValidatorFactory;

    public ValidationWorker(
        IStoreOrders orderStore,
        IStoreAccounts accountStore,
        IChallengeValidatorFactory challengeValidatorFactory)
    {
        _orderStore = orderStore;
        _accountStore = accountStore;
        _challengeValidatorFactory = challengeValidatorFactory;
    }

    public async Task Run(CancellationToken cancellationToken)
    {
        var orders = await _orderStore.GetValidatableOrders(cancellationToken).ConfigureAwait(false);

        var tasks = new Task[orders.Count];
        for (var i = 0; i < orders.Count; ++i)
        {
            tasks[i] = ValidateOrder(orders[i], cancellationToken);
        }

        Task.WaitAll(tasks, cancellationToken);
    }

    private async Task ValidateOrder(Order order, CancellationToken cancellationToken)
    {
        var account = await _accountStore.LoadAccount(order.AccountId, cancellationToken).ConfigureAwait(false);
        if (account == null)
        {
            order.SetStatus(OrderStatus.Invalid);
            order.Error = new AcmeError("accountDoesNotExist", "Account could not be located. Order will be marked invalid.");
            await _orderStore.SaveOrder(order, cancellationToken).ConfigureAwait(false);

            return;
        }

        var pendingAuthZs =
            order.Authorizations.Where(a => a.Challenges.Any(c => c.Status == ChallengeStatus.Processing));

        foreach (var pendingAuthZ in pendingAuthZs)
        {
            if (pendingAuthZ.Expires <= DateTimeOffset.UtcNow)
            {
                pendingAuthZ.ClearChallenges();
                pendingAuthZ.SetStatus(AuthorizationStatus.Expired);
                order.Error = new AcmeError("unauthorized", "Authorization expired", pendingAuthZ.Identifier);
                continue;
            }

            var challenge = pendingAuthZ.Challenges[0];

            AcmeInstruments.ChallengeValidationRequests.Add(1);
            AcmeInstruments.ChallengeValidationActive.Add(1);
            var sw = Stopwatch.GetTimestamp();
            using var activity = AcmeInstruments.ActivitySource.StartActivity(ActivityNames.ChallengeValidation);
            try
            {
                var validator = _challengeValidatorFactory.GetValidator(challenge);
                var (isValid, error) = await validator.ValidateChallenge(challenge, account, cancellationToken).ConfigureAwait(false);

                if (isValid)
                {
                    challenge.Error = null;
                    challenge.Validated = DateTimeOffset.UtcNow;
                    challenge.SetStatus(ChallengeStatus.Valid);
                    pendingAuthZ.SetStatus(AuthorizationStatus.Valid);
                    if (order.Error != null && string.Equals(order.Error.Type, "urn:ietf:params:acme:error:unauthorized", StringComparison.Ordinal))
                    {
                        order.Error = null;
                    }

                    AcmeInstruments.ChallengeValidationSuccesses.Add(1);
                    activity?.SetStatus(ActivityStatusCode.Ok);
                }
                else
                {
                    challenge.Error = error ?? new AcmeError("serverInternal", "Challenge validation failed.", pendingAuthZ.Identifier);
                    challenge.SetStatus(ChallengeStatus.Invalid);
                    pendingAuthZ.SetStatus(AuthorizationStatus.Invalid);
                    order.Error = challenge.Error;
                    AcmeInstruments.ChallengeValidationFailures.Add(1);
                    activity?.SetStatus(ActivityStatusCode.Error);
                }
            }
            catch (Exception ex)
            {
                AcmeInstruments.ChallengeValidationFailures.Add(1);
                activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
                throw;
            }
            finally
            {
                AcmeInstruments.ChallengeValidationActive.Add(-1);
                AcmeInstruments.ChallengeValidationDuration.Record(Stopwatch.GetElapsedTime(sw).TotalSeconds);
            }
        }

        order.SetStatusFromAuthorizations();
        await _orderStore.SaveOrder(order, cancellationToken).ConfigureAwait(false);
    }
}
