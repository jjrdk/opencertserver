namespace OpenCertServer.Acme.Server.Controllers
{
    using System.Security.Cryptography.X509Certificates;
    using Abstractions.HttpModel.Requests;
    using Abstractions.Model;
    using Abstractions.Model.Exceptions;
    using Abstractions.Services;
    using Ca.Utils;
    using Certes;
    using Certes.Acme;
    using Filters;
    using Microsoft.AspNetCore.Mvc;

    [AddNextNonce]
    public class OrderController : ControllerBase
    {
        private readonly IOrderService _orderService;
        private readonly IAccountService _accountService;

        public OrderController(IOrderService orderService, IAccountService accountService)
        {
            _orderService = orderService;
            _accountService = accountService;
        }

        [Route("/new-order", Name = "NewOrder")]
        [HttpPost]
        public async Task<ActionResult<Abstractions.HttpModel.Order>> CreateOrder(
            AcmePayload<CreateOrderRequest> payload)
        {
            var account = await _accountService.FromRequest(HttpContext.RequestAborted);

            var orderRequest = payload.Value;

            if (orderRequest.Identifiers?.Any() != true)
            {
                throw new MalformedRequestException("No identifiers submitted");
            }

            foreach (var i in orderRequest.Identifiers.Where(
                         i => string.IsNullOrWhiteSpace(i.Type) || string.IsNullOrWhiteSpace(i.Value)))
            {
                throw new MalformedRequestException($"Malformed identifier: (Type: {i.Type}, Value: {i.Value})");
            }

            var identifiers =
                orderRequest.Identifiers.Select(x => new Abstractions.Model.Identifier(x.Type!, x.Value!));

            var order = await _orderService.CreateOrder(
                account,
                identifiers,
                orderRequest.NotBefore,
                orderRequest.NotAfter,
                HttpContext.RequestAborted);

            GetOrderUrls(order, out var authorizationUrls, out var finalizeUrl, out var certificateUrl);
            var orderResponse = new Abstractions.HttpModel.Order(order, authorizationUrls, finalizeUrl, certificateUrl);

            var orderUrl = Url.RouteUrl("GetOrder", new { orderId = order.OrderId }, "https")!;
            return new CreatedResult(orderUrl, orderResponse);
        }

        private void GetOrderUrls(
            Order order,
            out IEnumerable<string> authorizationUrls,
            out string finalizeUrl,
            out string certificateUrl)
        {
            authorizationUrls = order.Authorizations.Select(
                x => Url.RouteUrl(
                    nameof(GetAuthorization),
                    new { orderId = order.OrderId, authId = x.AuthorizationId },
                    "https")!);
            finalizeUrl = Url.RouteUrl(nameof(FinalizeOrder), new { orderId = order.OrderId }, "https")!;
            certificateUrl = Url.RouteUrl(nameof(GetCertificate), new { orderId = order.OrderId }, "https")!;
        }

        [Route("/order/{orderId}", Name = "GetOrder")]
        [HttpPost]
        public async Task<ActionResult<Abstractions.HttpModel.Order>> GetOrder(string orderId)
        {
            var account = await _accountService.FromRequest(HttpContext.RequestAborted);
            var order = await _orderService.GetOrderAsync(account, orderId, HttpContext.RequestAborted);

            if (order == null)
            {
                return NotFound();
            }

            GetOrderUrls(order, out var authorizationUrls, out var finalizeUrl, out var certificateUrl);
            var orderResponse = new Abstractions.HttpModel.Order(order, authorizationUrls, finalizeUrl, certificateUrl);

            return orderResponse;
        }

        [Route("/order/{orderId}/auth/{authId}", Name = "GetAuthorization")]
        [HttpPost]
        public async Task<ActionResult<Abstractions.HttpModel.Authorization>> GetAuthorization(
            string orderId,
            string authId)
        {
            var account = await _accountService.FromRequest(HttpContext.RequestAborted);
            var order = await _orderService.GetOrderAsync(account, orderId, HttpContext.RequestAborted);

            if (order == null)
            {
                return NotFound();
            }

            var authZ = order.GetAuthorization(authId);
            if (authZ == null)
            {
                return NotFound();
            }

            var challenges = authZ.Challenges.Select(
                challenge =>
                {
                    var challengeUrl = GetChallengeUrl(challenge);

                    return new Abstractions.HttpModel.Challenge(challenge, challengeUrl);
                });

            var authZResponse = new Abstractions.HttpModel.Authorization(authZ, challenges);

            return authZResponse;
        }

        private string GetChallengeUrl(Challenge challenge)
        {
            return Url.RouteUrl(
                "AcceptChallenge",
                new
                {
                    orderId = challenge.Authorization.Order.OrderId,
                    authId = challenge.Authorization.AuthorizationId,
                    challengeId = challenge.ChallengeId
                },
                "https")!;
        }

        [Route("/order/{orderId}/auth/{authId}/chall/{challengeId}", Name = "AcceptChallenge")]
        [HttpPost]
        [AcmeLocation("GetOrder")]
        public async Task<ActionResult<Abstractions.HttpModel.Challenge>> AcceptChallenge(
            string orderId,
            string authId,
            string challengeId)
        {
            var account = await _accountService.FromRequest(HttpContext.RequestAborted);
            var challenge = await _orderService.ProcessChallenge(
                account,
                orderId,
                authId,
                challengeId,
                HttpContext.RequestAborted);

            if (challenge == null)
            {
                throw new NotFoundException();
            }

            var challengeResponse = new Abstractions.HttpModel.Challenge(challenge, GetChallengeUrl(challenge));
            return challengeResponse;
        }

        [Route("/order/{orderId}/finalize", Name = "FinalizeOrder")]
        [HttpPost]
        [AcmeLocation("GetOrder")]
        public async Task<ActionResult<Abstractions.HttpModel.Order>> FinalizeOrder(
            string orderId,
            AcmePayload<FinalizeOrderRequest> payload)
        {
            var account = await _accountService.FromRequest(HttpContext.RequestAborted);
            var order = await _orderService.ProcessCsr(account, orderId, payload.Value.Csr, HttpContext.RequestAborted);

            GetOrderUrls(order, out var authorizationUrls, out var finalizeUrl, out var certificateUrl);

            var orderResponse = new Abstractions.HttpModel.Order(order, authorizationUrls, finalizeUrl, certificateUrl);
            return orderResponse;
        }

        [Route("/order/{orderId}/certificate", Name = "GetCertificate")]
        [HttpPost]
        [AcmeLocation("GetOrder")]
        public async Task<IActionResult> GetCertificate(string orderId)
        {
            var account = await _accountService.FromRequest(HttpContext.RequestAborted);
            var certificateChainBytes = await _orderService.GetCertificate(account, orderId, HttpContext.RequestAborted);
            
            return File(certificateChainBytes, "application/pem-certificate-chain");
        }
    }
}
