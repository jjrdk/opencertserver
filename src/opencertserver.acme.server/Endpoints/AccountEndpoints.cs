using System.Text.Json;
using CertesSlim.Acme.Resource;
using CertesSlim.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Server.Filters;
using Account = OpenCertServer.Acme.Abstractions.HttpModel.Account;

namespace OpenCertServer.Acme.Server.Endpoints;

public static class AccountEndpoints
{
    public static IEndpointRouteBuilder MapAccountEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/new-account", async (
            HttpContext context,
            [FromServices] IAccountService accountService,
            JwsPayload jwsPayload,
            [FromServices] LinkGenerator links,
            CancellationToken cancellationToken) =>
        {
            var header = JsonSerializer.Deserialize<AcmeHeader>(Base64UrlEncoder.Decode(jwsPayload.Protected)!,
                AcmeSerializerContext.Default.AcmeHeader)!;
            var payload = JsonSerializer.Deserialize<CreateOrGetAccount>(
                Base64UrlEncoder.Decode(jwsPayload.Payload), AcmeSerializerContext.Default.CreateOrGetAccount)!;
            if (payload == null)
            {
                throw new MalformedRequestException("Payload was empty or could not be read.");
            }

            if (header.Jwk == null)
            {
                throw new MalformedRequestException("Account creation requests must be signed with a JWK.");
            }

            if (payload.OnlyReturnExisting)
            {
                var account = await accountService.FindAccount(header.Jwk, cancellationToken).ConfigureAwait(false);
                if (account == null)
                {
                    throw new AccountDoesNotExistException();
                }

                var accountUrl = GetAccountUrl(context, links, account.AccountId);
                context.Response.Headers.Location = accountUrl;
                var accountResponse = CreateAccountResponse(context, links, account);
                return Results.Ok(accountResponse);
            }

            var createdAccount = await accountService.CreateAccount(
                header.Jwk,
                payload.Contact,
                payload.TermsOfServiceAgreed == true,
                cancellationToken).ConfigureAwait(false);
            var createdAccountResponse = CreateAccountResponse(context, links, createdAccount);
            var createdAccountUrl = GetAccountUrl(context, links, createdAccount.AccountId);
            return Results.Created(createdAccountUrl, createdAccountResponse);
        }).WithName("NewAccount");

        endpoints.MapMethods("/account/{accountId}", ["POST", "PUT"], [AcmeLocation("Account")] async (
            HttpContext context,
            string accountId,
            JwsPayload payload,
            IAccountService accountService,
            LinkGenerator links,
            CancellationToken cancellationToken) =>
        {
            var account = await accountService.FromRequest(payload.ToAcmeHeader(), cancellationToken).ConfigureAwait(false);
            ValidateAccountRoute(accountId, account);

            if (IsPostAsGet(payload))
            {
                return Results.Ok(CreateAccountResponse(context, links, account));
            }

            var request = payload.ToPayload<UpdateAccountRequest>();
            if (request == null)
            {
                throw new MalformedRequestException("Payload was empty or could not be read.");
            }

            if (request.Status == AccountStatus.Deactivated)
            {
                account = await accountService.DeactivateAccount(account, cancellationToken).ConfigureAwait(false);
                return Results.Ok(CreateAccountResponse(context, links, account));
            }

            if (request.Status.HasValue && request.Status != AccountStatus.Valid)
            {
                throw new ConflictRequestException(request.Status.Value);
            }

            var updatedAccount = await accountService.UpdateAccount(
                account,
                request.Contact ?? account.Contacts,
                request.TermsOfServiceAgreed == true,
                cancellationToken).ConfigureAwait(false);
            return Results.Ok(CreateAccountResponse(context, links, updatedAccount));
        }).WithName("Account").AddEndpointFilter<AcmeLocationFilter>();

        endpoints.MapPost("/account/{accountId}/orders", async (
            HttpContext context,
            string accountId,
            JwsPayload payload,
            IOrderService orderService,
            IAccountService accountService,
            LinkGenerator links,
            CancellationToken cancellationToken) =>
        {
            var account = await accountService.FromRequest(payload.ToAcmeHeader(), cancellationToken).ConfigureAwait(false);
            ValidateAccountRoute(accountId, account);

            var orderIds = await orderService.GetOrderIds(account, cancellationToken).ConfigureAwait(false);
            var orders = orderIds
                .Select(orderId => new Uri(GetOrderUrl(context, links, orderId)))
                .ToList();

            return Results.Ok(new { orders });
        }).WithName("OrderList");

        return endpoints;
    }

    private static Account CreateAccountResponse(HttpContext context, LinkGenerator links, Abstractions.Model.Account account)
    {
        var ordersUrl = GetOrdersUrl(context, links, account.AccountId);
        return new Account(account, ordersUrl);
    }

    private static string GetAccountUrl(HttpContext context, LinkGenerator links, string accountId)
        => links.GetUriByName(
            context,
            "Account",
            new RouteValueDictionary([KeyValuePair.Create<string, string?>("accountId", accountId)]),
            scheme: Uri.UriSchemeHttps) ?? string.Empty;

    private static string GetOrdersUrl(HttpContext context, LinkGenerator links, string accountId)
        => links.GetUriByName(
            context,
            "OrderList",
            new RouteValueDictionary([KeyValuePair.Create<string, string?>("accountId", accountId)]),
            scheme: Uri.UriSchemeHttps) ?? string.Empty;

    private static string GetOrderUrl(HttpContext context, LinkGenerator links, string orderId)
        => links.GetUriByName(
            context,
            "GetOrder",
            new RouteValueDictionary([KeyValuePair.Create<string, string?>("orderId", orderId)]),
            scheme: Uri.UriSchemeHttps) ?? string.Empty;

    private static bool IsPostAsGet(JwsPayload payload)
        => string.IsNullOrEmpty(payload.Payload);

    private static void ValidateAccountRoute(string accountId, Abstractions.Model.Account account)
    {
        if (!string.Equals(account.AccountId, accountId, StringComparison.Ordinal))
        {
            throw new NotAllowedException();
        }
    }
}
