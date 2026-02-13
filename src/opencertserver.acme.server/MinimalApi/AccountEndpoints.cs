using System.Text.Json;
using CertesSlim.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;
using OpenCertServer.Acme.Abstractions.Model.Exceptions;
using OpenCertServer.Acme.Abstractions.Services;
using Account = OpenCertServer.Acme.Abstractions.HttpModel.Account;

namespace OpenCertServer.Acme.Server.MinimalApi;

public static class AccountEndpoints
{
    public static IEndpointRouteBuilder MapAccountEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/new-account", async (
            [FromServices] IAccountService accountService,
            JwsPayload jwsPayload,
            [FromServices] LinkGenerator links,
            CancellationToken cancellationToken) =>
        {
            var header = JsonSerializer.Deserialize<AcmeHeader>(Base64UrlEncoder.Decode(jwsPayload.Protected)!,
                AcmeSerializerContext.Default.AcmeHeader)!;
            var payload = JsonSerializer.Deserialize<CreateOrGetAccount>(
                Base64UrlEncoder.Decode(jwsPayload.Payload), AcmeSerializerContext.Default.CreateOrGetAccount)!;
            if (payload.OnlyReturnExisting)
            {
                var account = await accountService.FindAccount(header.Jwk!, cancellationToken);
                var routeDic =
                    new RouteValueDictionary([KeyValuePair.Create<string, string?>("accountId", account?.AccountId)]);
                var ordersUrl = links.GetPathByName("OrderList", routeDic) ?? string.Empty;
                var accountResponse = new Account(account!, ordersUrl);
                return Results.Ok(accountResponse);
            }
            else
            {
                if (payload == null)
                {
                    throw new MalformedRequestException("Payload was empty or could not be read.");
                }

                var account = await accountService.CreateAccount(
                    header.Jwk!,
                    payload.Contact,
                    payload.TermsOfServiceAgreed,
                    cancellationToken);
                var routeDic =
                    new RouteValueDictionary([KeyValuePair.Create<string, string?>("accountId", account.AccountId)]);
                var ordersUrl = links.GetPathByName("OrderList", routeDic) ?? string.Empty;
                var accountResponse = new Account(account, ordersUrl);
                var accountUrl = links.GetPathByName("Account", routeDic) ?? string.Empty;
                return Results.Created(accountUrl, accountResponse);
            }
        }).WithName("NewAccount");

        endpoints.MapMethods("/account/{accountId}", ["POST", "PUT"], (string accountId) =>
        {
            // Not implemented
            return Results.StatusCode(501);
        }).WithName("Account");

        endpoints.MapPost("/account/{accountId}/orders", (string accountId, JwsPayload payload) =>
        {
            // Not implemented
            return Results.StatusCode(501);
        }).WithName("OrderList");

        return endpoints;
    }
}
