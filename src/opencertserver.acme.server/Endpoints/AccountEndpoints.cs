namespace OpenCertServer.Acme.Server.Endpoints;

using System.Text;
using System.Text.Json;
using CertesSlim.Acme.Resource;
using CertesSlim.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Configuration;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Server.Filters;
using Account = OpenCertServer.Acme.Abstractions.HttpModel.Account;

public static class AccountEndpoints
{
    public static IEndpointRouteBuilder MapAccountEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/new-account", NewAccountHandler).WithName("NewAccount");

        endpoints.MapPost("/key-change", KeyChangeHandler).WithName("KeyChange");

        endpoints.MapMethods(
                "/account/{accountId}",
                [HttpMethods.Post, HttpMethods.Put],
                AccountIdHandler)
            .WithName("Account").AddEndpointFilter<AcmeLocationFilter>();

        endpoints.MapPost("/account/{accountId}/orders", AccounterOrdersHandler).WithName("OrderList");

        return endpoints;
    }

    private static async Task<IResult> AccounterOrdersHandler(HttpContext context, string accountId, JwsPayload payload, IOrderService orderService, IAccountService accountService, LinkGenerator links, CancellationToken cancellationToken)
    {
        var account = await accountService.FromRequest(payload.ToAcmeHeader(), cancellationToken)
            .ConfigureAwait(false);
        ValidateAccountRoute(accountId, account);

        var orderIds = await orderService.GetOrderIds(account, cancellationToken).ConfigureAwait(false);
        var orders = orderIds.Select(orderId => new Uri(GetOrderUrl(context, links, orderId)))
            .ToList();

        return Results.Ok(new { orders });
    }

    [AcmeLocation("Account")]
    private static async Task<IResult> AccountIdHandler(
        HttpContext context,
        string accountId,
        JwsPayload payload,
        IAccountService accountService,
        LinkGenerator links,
        CancellationToken cancellationToken)
    {
        // RFC 8555 §7.3.6: The server MUST still allow clients to access the account
        // in a read-only manner (POST-as-GET) even after deactivation.
        // Bind the authenticated account from the JWS kid header and verify it matches
        // the route parameter before loading, to prevent privilege escalation.
        var authenticatedAccountId = payload.ToAcmeHeader().GetAccountId();
        ValidateAccountRoute(accountId, authenticatedAccountId);

        var account = await accountService.LoadAccount(authenticatedAccountId, cancellationToken).ConfigureAwait(false);
        if (account == null)
        {
            throw new NotFoundException();
        }

        if (IsPostAsGet(payload))
        {
            // POST-as-GET is a read-only operation – allowed even for deactivated accounts.
            return Results.Ok(CreateAccountResponse(context, links, account));
        }

        // All mutating operations require the account to be in a valid (active) state.
        if (account.Status != AccountStatus.Valid)
        {
            throw new ConflictRequestException(AccountStatus.Valid, account.Status);
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

        var updatedAccount = await accountService.UpdateAccount(account, request.Contact ?? account.Contacts,
            request.TermsOfServiceAgreed == true, cancellationToken).ConfigureAwait(false);
        return Results.Ok(CreateAccountResponse(context, links, updatedAccount));
    }

    private static async Task<IResult> KeyChangeHandler(
        HttpContext context,
        JwsPayload payload,
        IAccountService accountService,
        LinkGenerator links,
        CancellationToken cancellationToken)
    {
        // RFC 8555 §7.3.5: The outer JWS is signed by the CURRENT (old) account key and
        // must identify the account with a "kid" header parameter.
        // The request validation middleware has already verified the outer signature via kid.
        var outerHeader = payload.ToAcmeHeader();
        if (outerHeader.Kid == null)
        {
            throw new MalformedRequestException("The outer keyChange request must identify the account with a Kid.");
        }

        var account = await accountService.FromRequest(outerHeader, cancellationToken).ConfigureAwait(false);

        // RFC 8555 §7.3.5: The inner JWS is signed by the NEW key and must carry the new
        // key in its "jwk" header parameter (no "kid" is permitted in the inner JWS).
        var nestedPayload = payload.ToPayload<JwsPayload>();
        ValidateNestedJwsEnvelope(nestedPayload);
        var innerPayload = nestedPayload!;

        var nestedHeader = innerPayload.ToAcmeHeader();
        if (nestedHeader.Jwk == null || nestedHeader.Kid != null)
        {
            throw new MalformedRequestException(
                "The inner keyChange request must be signed with a JWK (the new key) and must not contain a Kid.");
        }

        // RFC 8555 §7.3.5: The inner JWS must NOT contain a nonce.
        if (!string.IsNullOrWhiteSpace(nestedHeader.Nonce))
        {
            throw new MalformedRequestException("The inner keyChange JWS must not contain a nonce.");
        }

        // RFC 8555 §7.3.5: The "url" in the inner JWS protected header must match the outer request URL.
        if (string.IsNullOrWhiteSpace(nestedHeader.Url))
        {
            throw new MalformedRequestException("The inner keyChange JWS must contain a non-empty url.");
        }

        var expectedUrl = context.Request.GetDisplayUrl();
        if (!string.Equals(nestedHeader.Url, expectedUrl, StringComparison.Ordinal))
        {
            throw new NotAuthorizedException();
        }

        // Verify the inner JWS using the new key carried in the inner "jwk" header.
        var newKey = nestedHeader.Jwk;
        VerifyNestedSignature(innerPayload, newKey, nestedHeader.Alg);

        var keyChange = innerPayload.ToPayload<KeyChangeRequest>();
        if (keyChange?.Account == null || keyChange.OldKey == null)
        {
            throw new MalformedRequestException("The keyChange request payload was empty or malformed.");
        }

        // RFC 8555 §7.3.5: The "account" field in the inner payload must match the account URL.
        var accountUrl = GetAccountUrl(context, links, account.AccountId);
        if (!Uri.TryCreate(accountUrl, UriKind.Absolute, out var expectedAccountUrl) ||
            keyChange.Account != expectedAccountUrl)
        {
            throw new MalformedRequestException("The nested keyChange request must identify the current account URL.");
        }

        // RFC 8555 §7.3.5: The "oldKey" field must match the account's current key.
        if (!KeysMatch(account.Jwk, keyChange.OldKey))
        {
            throw new NotAuthorizedException();
        }

        account = await accountService.ChangeKey(account, newKey, cancellationToken).ConfigureAwait(false);
        context.Response.Headers.Location = accountUrl;
        return Results.Ok(CreateAccountResponse(context, links, account));
    }

    private static async Task<IResult> NewAccountHandler(
        HttpContext context,
        [FromServices] IAccountService accountService,
        [FromServices] IOptions<AcmeServerOptions> optionsAccessor,
        [FromServices] IExternalAccountBindingService eabService,
        JwsPayload jwsPayload,
        [FromServices] LinkGenerator links,
        CancellationToken cancellationToken)
    {
        var options = optionsAccessor.Value;
        var header = JsonSerializer.Deserialize<AcmeHeader>(Base64UrlEncoder.Decode(jwsPayload.Protected)!,
            AcmeSerializerContext.Default.AcmeHeader)!;
        var payload = JsonSerializer.Deserialize<CreateOrGetAccount>(Base64UrlEncoder.Decode(jwsPayload.Payload),
            AcmeSerializerContext.Default.CreateOrGetAccount)!;
        if (payload == null)
        {
            throw new MalformedRequestException("Payload was empty or could not be read.");
        }

        if (header.Jwk == null)
        {
            throw new MalformedRequestException("Account creation requests must be signed with a JWK.");
        }

        switch (payload.OnlyReturnExisting)
        {
            case false when options.TOS.RequireAgreement && payload.TermsOfServiceAgreed != true:
                throw new MalformedRequestException("The ACME server requires agreement to the current terms of service.");
            case false when options.ExternalAccountRequired && !HasExternalAccountBinding(payload):
                throw new MalformedRequestException("The ACME server requires a valid externalAccountBinding.");
            case true:
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
        }

        // Validate EAB when present (required or voluntary)
        string? externalAccountId = null;
        if (HasExternalAccountBinding(payload))
        {
            var requestUrl = context.Request.GetDisplayUrl();
            externalAccountId = await eabService
                .ValidateAsync(payload.ExternalAccountBinding!.Value, header.Jwk, requestUrl, cancellationToken)
                .ConfigureAwait(false);

            // Consume the EAB key before creating the account so single-use keys
            // cannot be raced and a failed key save does not leave an orphan account.
            var eabStore = context.RequestServices
                .GetRequiredService<OpenCertServer.Acme.Abstractions.Storage.IStoreExternalAccountKeys>();
            var eabKey = await eabStore.LoadKey(externalAccountId, cancellationToken).ConfigureAwait(false);
            if (eabKey != null)
            {
                eabKey.MarkUsed(null);
                await eabStore.SaveKey(eabKey, cancellationToken).ConfigureAwait(false);
            }
        }

        var createdAccount = await accountService.CreateAccount(header.Jwk, payload.Contact,
            payload.TermsOfServiceAgreed == true, externalAccountId, cancellationToken).ConfigureAwait(false);
        var createdAccountResponse = CreateAccountResponse(context, links, createdAccount);
        var createdAccountUrl = GetAccountUrl(context, links, createdAccount.AccountId);
        return Results.Created(createdAccountUrl, createdAccountResponse);
    }

    private static Account CreateAccountResponse(
        HttpContext context,
        LinkGenerator links,
        Abstractions.Model.Account account)
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

    private static bool HasExternalAccountBinding(CreateOrGetAccount payload)
        => payload.ExternalAccountBinding is { ValueKind: not JsonValueKind.Null and not JsonValueKind.Undefined };

    private static void ValidateNestedJwsEnvelope(JwsPayload? payload)
    {
        if (payload == null)
        {
            throw new MalformedRequestException("The nested keyChange request was missing.");
        }

        if (string.IsNullOrWhiteSpace(payload.Protected) || payload.Payload == null ||
            string.IsNullOrWhiteSpace(payload.Signature))
        {
            throw new MalformedRequestException("The nested keyChange request must be a flattened JWS object.");
        }
    }

    private static void VerifyNestedSignature(JwsPayload payload, JsonWebKey jwk, string? algorithm)
    {
        if (string.IsNullOrWhiteSpace(algorithm))
        {
            throw new MalformedRequestException("The nested keyChange protected header must contain an algorithm.");
        }

        try
        {
            using var signatureProvider = new AsymmetricSignatureProvider(jwk, algorithm);
            var plainText = Encoding.UTF8.GetBytes($"{payload.Protected}.{payload.Payload ?? string.Empty}");
            var signature = Base64UrlEncoder.DecodeBytes(payload.Signature);
            if (!signatureProvider.Verify(plainText, signature))
            {
                throw new MalformedRequestException("The nested keyChange signature could not be verified.");
            }
        }
        catch (ArgumentException)
        {
            throw new BadSignatureAlgorithmException();
        }
        catch (NotSupportedException)
        {
            throw new BadSignatureAlgorithmException();
        }
    }


    private static bool KeysMatch(JsonWebKey left, JsonWebKey right)
        => string.Equals(
            Base64UrlEncoder.Encode(left.ComputeJwkThumbprint()),
            Base64UrlEncoder.Encode(right.ComputeJwkThumbprint()),
            StringComparison.Ordinal);

    private static void ValidateAccountRoute(string routeAccountId, string authenticatedAccountId)
    {
        if (!string.Equals(authenticatedAccountId, routeAccountId, StringComparison.Ordinal))
        {
            throw new NotAllowedException();
        }
    }

    private static void ValidateAccountRoute(string routeAccountId, Abstractions.Model.Account account)
        => ValidateAccountRoute(routeAccountId, account.AccountId);
}
