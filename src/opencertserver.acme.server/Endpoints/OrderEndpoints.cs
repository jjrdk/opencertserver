using CertesSlim.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Server.Filters;

namespace OpenCertServer.Acme.Server.Endpoints;

public static class OrderEndpoints
{
    public static IEndpointRouteBuilder MapOrderEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/new-order", async (
            HttpContext context,
            IOrderService orderService,
            IAccountService accountService,
            JwsPayload payload,
            LinkGenerator links,
            CancellationToken cancellationToken) =>
        {
            var header = payload.ToAcmeHeader();
            var account = await accountService.FromRequest(header, cancellationToken);
            var orderRequest = payload.ToPayload<CreateOrderRequest>();
            if (orderRequest?.Identifiers?.Count == 0)
            {
                throw new MalformedRequestException("No identifiers submitted");
            }

            foreach (var i in orderRequest!.Identifiers!.Where(i =>
                string.IsNullOrWhiteSpace(i.Type) || string.IsNullOrWhiteSpace(i.Value)))
                throw new MalformedRequestException($"Malformed identifier: (Type: {i.Type}, Value: {i.Value})");
            var identifiers = orderRequest.Identifiers!.Select(x =>
                new OpenCertServer.Acme.Abstractions.Model.Identifier(x.Type!, x.Value!));
            var order = await orderService.CreateOrder(account, identifiers, orderRequest.NotBefore,
                orderRequest.NotAfter, cancellationToken);
            GetOrderUrls(context, links, order, out var authorizationUrls, out var finalizeUrl, out var certificateUrl);
            var orderResponse =
                new OpenCertServer.Acme.Abstractions.HttpModel.Order(order, authorizationUrls, finalizeUrl,
                    certificateUrl);
            var orderUrl = links.GetUriByName(context,
                    "GetOrder",
                    new RouteValueDictionary([KeyValuePair.Create<string, string?>("orderId", order.OrderId)]),
                    scheme: Uri.UriSchemeHttps) ??
                string.Empty;
            return Results.Created(orderUrl, orderResponse);
        }).WithName("NewOrder");

        endpoints.MapPost("/order/{orderId}", async (
            HttpContext context,
            string orderId,
            JwsPayload payload,
            IOrderService orderService,
            IAccountService accountService,
            LinkGenerator links,
            CancellationToken cancellationToken) =>
        {
            var account = await accountService.FromRequest(payload.ToAcmeHeader(), cancellationToken);
            var order = await orderService.GetOrderAsync(account, orderId, cancellationToken);
            if (order == null) return Results.NotFound();
            GetOrderUrls(context, links, order, out var authorizationUrls, out var finalizeUrl, out var certificateUrl);
            var orderResponse =
                new OpenCertServer.Acme.Abstractions.HttpModel.Order(order, authorizationUrls, finalizeUrl,
                    certificateUrl);
            return Results.Ok(orderResponse);
        }).WithName("GetOrder");

        endpoints.MapPost("/order/{orderId}/auth/{authId}", async (
            HttpContext context,
            string orderId,
            string authId,
            JwsPayload payload,
            IOrderService orderService,
            IAccountService accountService,
            LinkGenerator links,
            CancellationToken cancellationToken) =>
        {
            var account = await accountService.FromRequest(payload.ToAcmeHeader(), cancellationToken);
            var order = await orderService.GetOrderAsync(account, orderId, cancellationToken);
            if (order == null) return Results.NotFound();
            var authZ = order.GetAuthorization(authId);
            if (authZ == null) return Results.NotFound();
            var challenges = authZ.Challenges.Select(challenge =>
                new OpenCertServer.Acme.Abstractions.HttpModel.Challenge(challenge,
                    GetChallengeUrl(context, links, challenge)));
            var authZResponse = new OpenCertServer.Acme.Abstractions.HttpModel.Authorization(authZ, challenges);
            return Results.Ok(authZResponse);
        }).WithName("GetAuthorization");

        endpoints.MapPost("/order/{orderId}/auth/{authId}/chall/{challengeId}", [AcmeLocation("GetOrder")] async (
            HttpContext context,
            string orderId,
            string authId,
            string challengeId,
            JwsPayload payload,
            IOrderService orderService,
            IAccountService accountService,
            LinkGenerator links,
            CancellationToken cancellationToken) =>
        {
            var account = await accountService.FromRequest(payload.ToAcmeHeader(), cancellationToken);
            var challenge =
                await orderService.ProcessChallenge(account, orderId, authId, challengeId, cancellationToken);
            if (challenge == null) return Results.NotFound();
            var challengeResponse =
                new OpenCertServer.Acme.Abstractions.HttpModel.Challenge(challenge,
                    GetChallengeUrl(context, links, challenge));
            return Results.Ok(challengeResponse);
        }).WithName("AcceptChallenge").AddEndpointFilter<AcmeLocationFilter>();

        endpoints.MapPost("/order/{orderId}/finalize", [AcmeLocation("GetOrder")] async (
            HttpContext context,
            string orderId,
            JwsPayload payload,
            IOrderService orderService,
            IAccountService accountService,
            LinkGenerator links,
            CancellationToken cancellationToken) =>
        {
            var account = await accountService.FromRequest(payload.ToAcmeHeader(), cancellationToken);
            var orderRequest = payload.ToPayload<FinalizeOrderRequest>();
            if (string.IsNullOrWhiteSpace(orderRequest?.Csr))
            {
                throw new MalformedRequestException("CSR was empty or could not be read.");
            }

            var order = await orderService.ProcessCsr(account, orderId, orderRequest.Csr, cancellationToken);
            GetOrderUrls(context, links, order, out var authorizationUrls, out var finalizeUrl, out var certificateUrl);
            var orderResponse =
                new OpenCertServer.Acme.Abstractions.HttpModel.Order(order, authorizationUrls, finalizeUrl,
                    certificateUrl);
            return Results.Ok(orderResponse);
        }).WithName("FinalizeOrder").AddEndpointFilter<AcmeLocationFilter>();

        endpoints.MapPost("/order/{orderId}/certificate", [AcmeLocation("GetOrder")] async (
            string orderId,
            JwsPayload payload,
            IOrderService orderService,
            IAccountService accountService,
            CancellationToken cancellationToken) =>
        {
            var account = await accountService.FromRequest(payload.ToAcmeHeader(), cancellationToken);
            var certificateChainBytes = await orderService.GetCertificate(account, orderId, cancellationToken);
            return Results.File(certificateChainBytes, "application/pem-certificate-chain");
        }).WithName("GetCertificate").AddEndpointFilter<AcmeLocationFilter>();

        return endpoints;
    }

    private static void GetOrderUrls(
        HttpContext context,
        LinkGenerator links,
        Order order,
        out IEnumerable<Uri> authorizationUrls,
        out Uri? finalizeUrl,
        out Uri? certificateUrl)
    {
        authorizationUrls = order.Authorizations.Select(x =>
        {
            var uri = links.GetUriByName(context,
                "GetAuthorization",
                new RouteValueDictionary([
                    KeyValuePair.Create<string, string?>("orderId", order.OrderId),
                    KeyValuePair.Create<string, string?>("authId", x.AuthorizationId)
                ]), scheme: Uri.UriSchemeHttps);
            return new Uri(uri!);
        });
        var routeDic = new RouteValueDictionary([
            KeyValuePair.Create<string, string?>("orderId", order.OrderId)
        ]);
        var fu = links.GetUriByName(context, "FinalizeOrder", routeDic, scheme: Uri.UriSchemeHttps);
        var cu = links.GetUriByName(context, "GetCertificate", routeDic, scheme: Uri.UriSchemeHttps);
        finalizeUrl = fu != null ? new Uri(fu) : null;
        certificateUrl = cu != null ? new Uri(cu) : null;
    }

    private static string GetChallengeUrl(HttpContext context, LinkGenerator links, Challenge challenge)
    {
        var routeDic = new RouteValueDictionary([
            KeyValuePair.Create<string, string?>("orderId", challenge.Authorization.Order.OrderId),
            KeyValuePair.Create<string, string?>("authId", challenge.Authorization.AuthorizationId),
            KeyValuePair.Create<string, string?>("challengeId", challenge.ChallengeId)
        ]);
        return links.GetUriByName(context, "AcceptChallenge", routeDic, scheme: Uri.UriSchemeHttps) ?? string.Empty;
    }
}
