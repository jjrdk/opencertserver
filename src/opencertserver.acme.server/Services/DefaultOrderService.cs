using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.IssuanceServices;
using Abstractions.Model;
using Abstractions.Services;
using Abstractions.Storage;

public sealed class DefaultOrderService : IOrderService
{
    private readonly IStoreOrders _orderStore;
    private readonly IAuthorizationFactory _authorizationFactory;
    private readonly ICsrValidator _csrValidator;
    private readonly IIssueCertificates _issuer;

    public DefaultOrderService(
        IStoreOrders orderStore,
        IAuthorizationFactory authorizationFactory,
        ICsrValidator csrValidator,
        IIssueCertificates issuer)
    {
        _orderStore = orderStore;
        _authorizationFactory = authorizationFactory;
        _csrValidator = csrValidator;
        _issuer = issuer;
    }

    public async Task<Order> CreateOrder(
        string? profile,
        Account account,
        IEnumerable<Identifier> identifiers,
        DateTimeOffset? notBefore,
        DateTimeOffset? notAfter,
        CancellationToken cancellationToken)
    {
        ValidateAccount(account);

        if (notBefore.HasValue && notAfter.HasValue && notAfter <= notBefore)
        {
            throw new MalformedRequestException("The requested validity window is invalid.");
        }

        var order = new Order(account, identifiers, profile) { NotBefore = notBefore, NotAfter = notAfter };

        _authorizationFactory.CreateAuthorizations(order);
        order.Expires = order.Authorizations.Min(a => a.Expires);

        await _orderStore.SaveOrder(order, cancellationToken).ConfigureAwait(false);

        return order;
    }

    public async Task<byte[]> GetCertificate(Account account, string orderId, CancellationToken cancellationToken)
    {
        ValidateAccount(account);
        var order = await HandleLoadOrder(account, orderId, OrderStatus.Valid, cancellationToken).ConfigureAwait(false);
        var chain = new CertificateChain(Encoding.UTF8.GetString(order.Certificate!)).Certificate.ExportCertificatePem();
        return Encoding.UTF8.GetBytes(chain);
    }

    public async Task<Order?> GetOrderAsync(Account account, string orderId, CancellationToken cancellationToken)
    {
        ValidateAccount(account);
        var order = await HandleLoadOrder(account, orderId, null, cancellationToken).ConfigureAwait(false);

        return order;
    }

    public async Task<IReadOnlyList<string>> GetOrderIds(Account account, CancellationToken cancellationToken)
    {
        ValidateAccount(account);
        return await _orderStore.GetOrderIds(account.AccountId, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Challenge?> ProcessChallenge(
        Account account,
        string orderId,
        string authId,
        string challengeId,
        CancellationToken cancellationToken)
    {
        ValidateAccount(account);

        var order = await HandleLoadOrder(account, orderId, null, cancellationToken).ConfigureAwait(false);

        var authZ = order.GetAuthorization(authId);
        var challenge = authZ?.GetChallenge(challengeId);

        if (authZ == null || challenge == null)
        {
            throw new NotFoundException();
        }

        if (authZ.Status != AuthorizationStatus.Pending || challenge.Status != ChallengeStatus.Pending)
        {
            return challenge;
        }

        challenge.SetStatus(ChallengeStatus.Processing);
        authZ.SelectChallenge(challenge);
        order.SetStatusFromAuthorizations();
        await _orderStore.SaveOrder(order, cancellationToken).ConfigureAwait(false);

        return challenge;
    }

    public async Task<Authorization> DeactivateAuthorization(
        Account account,
        string orderId,
        string authId,
        CancellationToken cancellationToken)
    {
        ValidateAccount(account);

        var order = await HandleLoadOrder(account, orderId, null, cancellationToken).ConfigureAwait(false);
        var authorization = order.GetAuthorization(authId);
        if (authorization == null)
        {
            throw new NotFoundException();
        }

        authorization.SetStatus(AuthorizationStatus.Deactivated);
        order.Error ??= new AcmeError("unauthorized", "Authorization was deactivated by the client.", authorization.Identifier);
        order.SetStatusFromAuthorizations();
        await _orderStore.SaveOrder(order, cancellationToken).ConfigureAwait(false);

        return authorization;
    }

    public async Task<Order> ProcessCsr(
        Account account,
        string orderId,
        string? csr,
        CancellationToken cancellationToken)
    {
        ValidateAccount(account);
        var order = await HandleLoadOrder(account, orderId, OrderStatus.Ready, cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(csr))
        {
            throw new MalformedRequestException("CSR may not be empty.");
        }

        var (isValid, error) = await _csrValidator.ValidateCsr(order, csr, cancellationToken).ConfigureAwait(false);

        if (isValid)
        {
            order.SetStatus(OrderStatus.Processing);
            order.CertificateSigningRequest = csr;
            var (certificate, acmeError) =
                await _issuer.IssueCertificate(
                    order.Profile,
                    csr,
                    order.Identifiers,
                    order.NotBefore,
                    order.NotAfter,
                    cancellationToken).ConfigureAwait(false);
            if (certificate != null)
            {
                order.Certificate = certificate;
                order.SetStatus(OrderStatus.Valid);
            }
            else if (acmeError != null)
            {
                order.Error = acmeError;
                order.SetStatus(OrderStatus.Invalid);
            }
        }
        else
        {
            if (error != null && string.Equals(error.Type, "urn:ietf:params:acme:error:badCSR", StringComparison.Ordinal))
            {
                throw new BadCsrException(error.Detail);
            }

            order.Error = error;
            order.SetStatus(OrderStatus.Invalid);
        }

        await _orderStore.SaveOrder(order, cancellationToken).ConfigureAwait(false);
        return order;
    }

    private static void ValidateAccount(Account? account)
    {
        if (account == null)
        {
            throw new NotAllowedException();
        }

        if (account.Status != AccountStatus.Valid)
        {
            throw new ConflictRequestException(AccountStatus.Valid, account.Status);
        }
    }

    private async Task<Order> HandleLoadOrder(
        Account account,
        string orderId,
        OrderStatus? expectedStatus,
        CancellationToken cancellationToken)
    {
        var order = await _orderStore.LoadOrder(orderId, cancellationToken).ConfigureAwait(false);
        if (order == null)
        {
            throw new NotFoundException();
        }

        if (expectedStatus.HasValue && order.Status != expectedStatus)
        {
            throw new ConflictRequestException(expectedStatus.Value, order.Status);
        }

        if (order.AccountId != account.AccountId)
        {
            throw new NotAllowedException();
        }

        return order;
    }
}
