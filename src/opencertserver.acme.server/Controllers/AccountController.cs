using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Acme.Server.Controllers;

using Abstractions.HttpModel.Requests;
using Abstractions.Model.Exceptions;
using Abstractions.Services;
using Filters;
using Microsoft.AspNetCore.Mvc;
using Account = Abstractions.HttpModel.Account;

//[AllowAnonymous]
[AddNextNonce]
public sealed class AccountController : ControllerBase
{
    private readonly IAccountService _accountService;

    public AccountController(IAccountService accountService)
    {
        _accountService = accountService;
    }

    [Route("/new-account", Name = "NewAccount")]
    [HttpPost]
    public async Task<ActionResult<Account>> CreateOrGetAccount(AcmeHeader header, AcmePayload<CreateOrGetAccount> payload)
    {
        if (payload.Value.OnlyReturnExisting)
        {
            return await FindAccount(header.Jwk!, payload);
        }

        return await CreateAccountAsync(header, payload);
    }

    private async Task<ActionResult<Account>> CreateAccountAsync(
        AcmeHeader header,
        AcmePayload<CreateOrGetAccount> payload)
    {
        if (payload == null)
        {
            throw new MalformedRequestException("Payload was empty or could not be read.");
        }

        var account = await _accountService.CreateAccount(
            header.Jwk!, //Post requests are validated, JWK exists.
            payload.Value.Contact,
            payload.Value.TermsOfServiceAgreed,
            HttpContext.RequestAborted);

        var ordersUrl = Url.RouteUrl("OrderList", new { accountId = account.AccountId }, "https")!;
        var accountResponse = new Account(account, ordersUrl);

        var accountUrl = Url.RouteUrl("Account", new { accountId = account.AccountId }, "https")!;
        return new CreatedResult(accountUrl, accountResponse);
    }

    private async Task<ActionResult<Account>> FindAccount(JsonWebKey jwk, AcmePayload<CreateOrGetAccount> payload)
    {
        var account = await _accountService.FindAccount(jwk);
        return
            new ActionResult<Account>(
                new Account(
                    account!,
                    Url.RouteUrl("OrderList", new { accountId = account!.AccountId }, "https")!));
    }

    [Route("/account/{accountId}", Name = "Account")]
    [HttpPost, HttpPut]
    public Task<ActionResult<Account>> SetAccount(string accountId)
    {
        throw new NotImplementedException();
    }

    [Route("/account/{accountId}/orders", Name = "OrderList")]
    [HttpPost]
    public Task<ActionResult<Abstractions.HttpModel.OrdersList>> GetOrdersList(string accountId, AcmePayload<object> payload)
    {
        throw new NotImplementedException();
    }
}
