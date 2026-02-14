using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Server.Workers;

using System;
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
        var orders = await _orderStore.GetValidatableOrders(cancellationToken);

        var tasks = new Task[orders.Count];
        for (var i = 0; i < orders.Count; ++i)
        {
            tasks[i] = ValidateOrder(orders[i], cancellationToken);
        }

        Task.WaitAll(tasks, cancellationToken);
    }

    private async Task ValidateOrder(Order order, CancellationToken cancellationToken)
    {
        var account = await _accountStore.LoadAccount(order.AccountId, cancellationToken);
        if (account == null)
        {
            order.SetStatus(OrderStatus.Invalid);
            order.Error = new AcmeError("TODO", "Account could not be located. Order will be marked invalid.");
            await _orderStore.SaveOrder(order, cancellationToken);

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
                continue;
            }

            var challenge = pendingAuthZ.Challenges[0];

            var validator = _challengeValidatorFactory.GetValidator(challenge);
            var (isValid, error) = await validator.ValidateChallenge(challenge, account, cancellationToken);

            if (isValid)
            {
                challenge.SetStatus(ChallengeStatus.Valid);
                pendingAuthZ.SetStatus(AuthorizationStatus.Valid);
            }
            else
            {
                challenge.Error = error!;
                challenge.SetStatus(ChallengeStatus.Invalid);
                pendingAuthZ.SetStatus(AuthorizationStatus.Invalid);
            }
        }

        order.SetStatusFromAuthorizations();
        await _orderStore.SaveOrder(order, cancellationToken);
    }
}
