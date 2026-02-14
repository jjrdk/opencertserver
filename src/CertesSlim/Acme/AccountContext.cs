using System.Security.Cryptography;
using System.Text.Json;
using CertesSlim.Acme.Resource;
using CertesSlim.Extensions;
using CertesSlim.Json;

namespace CertesSlim.Acme;

/// <summary>
/// Represents the context for ACME account operations.
/// </summary>
/// <seealso cref="IAccountContext" />
internal class AccountContext : EntityContext<Account>, IAccountContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AccountContext" /> class.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="location">The location.</param>
    public AccountContext(IAcmeContext context, Uri location)
        : base(context, location)
    {
    }

    /// <summary>
    /// Deactivates the current account.
    /// </summary>
    /// <returns>
    /// The account deactivated.
    /// </returns>
    public async Task<Account> Deactivate()
    {
        var payload = new Account { Status = AccountStatus.Deactivated };
        var resp = await Context.HttpClient.Post<Account, Account>(Context, Location, payload);
        return resp.Resource;
    }

    /// <summary>
    /// Gets the order list.
    /// </summary>
    /// <returns>
    /// The orders list.
    /// </returns>
    public async Task<IOrderListContext> Orders()
    {
        var account = await Resource();
        return new OrderListContext(Context, account.Orders!);
    }

    /// <summary>
    /// Updates the current account.
    /// </summary>
    /// <param name="contact">The contact infomation.</param>
    /// <param name="agreeTermsOfService">Set to <c>true</c> to accept the terms of service.</param>
    /// <returns>
    /// The account.
    /// </returns>
    public async Task<Account> Update(IList<string>? contact = null, bool agreeTermsOfService = false)
    {
        var location = await Context.Account().Location();
        var account = new Account
        {
            Contact = contact
        };

        if (agreeTermsOfService)
        {
            account.TermsOfServiceAgreed = true;
        }

        var response = await Context.HttpClient.Post<Account, Account>(Context, location, account);
        return response.Resource;
    }

    /// <summary>
    /// Post to the new account endpoint.
    /// </summary>
    /// <param name="context">The ACME context.</param>
    /// <param name="body">The payload.</param>
    /// <param name="eabKeyId">Optional key identifier, if using external account binding.</param>
    /// <param name="eabKey">Optional EAB key, if using external account binding.</param>
    /// <param name="eabKeyAlg">Optional EAB key algorithm, if using external account binding, defaults to HS256 if not specified</param>
    /// <returns>The ACME response.</returns>
    internal static async Task<AcmeHttpResponse<Account>> NewAccount(
        IAcmeContext context,
        Account body,
        string? eabKeyId = null,
        string? eabKey = null,
        string? eabKeyAlg = null)
    {
        var endpoint = await context.GetResourceUri(d => d.NewAccount);
        var jws = new JwsSigner(context.AccountKey);

        if (eabKeyId != null && eabKey != null)
        {
            var header = new Header
            {
                Alg = eabKeyAlg?.ToUpper() ?? "HS256",
                Kid = eabKeyId,
                Url = endpoint
            };

            var headerJson = JsonSerializer.Serialize(header, CertesSerializerContext.Default.Header);
            var protectedHeaderBase64 = System.Text.Encoding.UTF8.GetBytes(headerJson).ToBase64String();

            var accountKeyBase64 = System.Text.Encoding.UTF8.GetBytes(
                JsonSerializer.Serialize(context.AccountKey.JsonWebKey, CertesSerializerContext.Default.JsonWebKey)
            ).ToBase64String();

            var signingBytes = System.Text.Encoding.ASCII.GetBytes($"{protectedHeaderBase64}.{accountKeyBase64}");

            // eab signature is the hash of the header and account key, using the eab key
            byte[] signatureHash;

            switch (header.Alg)
            {
                case "HS512":
                    using (var hs512 = new HMACSHA512(eabKey.FromBase64String()))
                        signatureHash = hs512.ComputeHash(signingBytes);
                    break;
                case "HS384":
                    using (var hs384 = new HMACSHA384(eabKey.FromBase64String()))
                        signatureHash = hs384.ComputeHash(signingBytes);
                    break;
                default:
                    using (var hs256 = new HMACSHA256(eabKey.FromBase64String()))
                        signatureHash = hs256.ComputeHash(signingBytes);
                    break;
            }

            var signatureBase64 = signatureHash.ToBase64String();

            body.ExternalAccountBinding = new
            {
                Protected = protectedHeaderBase64,
                Payload = accountKeyBase64,
                Signature = signatureBase64
            };
        }

        return await context.HttpClient.Post<Account, Account>(jws, endpoint, body);
    }
}
