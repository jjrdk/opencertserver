using Certes.Acme;
using Certes.Acme.Resource;
using Certes.Extensions;
using Certes.Json;
using Microsoft.IdentityModel.Tokens;
using Directory = Certes.Acme.Resource.Directory;
using Identifier = Certes.Acme.Resource.Identifier;
using IdentifierType = Certes.Acme.Resource.IdentifierType;

namespace Certes;

/// <summary>
/// Represents the context for ACME operations.
/// </summary>
/// <seealso cref="Certes.IAcmeContext" />
public class AcmeContext : IAcmeContext
{
    private const string DefaultKeyType = SecurityAlgorithms.EcdsaSha256;
    private Directory? _directory;
    private IAccountContext? _accountContext;

    /// <summary>
    /// Gets the number of retries on a badNonce error.
    /// </summary>
    /// <value>
    /// The number of retries.
    /// </value>
    public int BadNonceRetryCount { get; }

    /// <summary>
    /// Gets the ACME HTTP client.
    /// </summary>
    /// <value>
    /// The ACME HTTP client.
    /// </value>
    public IAcmeHttpClient HttpClient { get; }

    /// <summary>
    /// Gets the directory URI.
    /// </summary>
    /// <value>
    /// The directory URI.
    /// </value>
    public Uri DirectoryUri { get; }

    /// <summary>
    /// Gets the account key.
    /// </summary>
    /// <value>
    /// The account key.
    /// </value>
    public IKey AccountKey { get; private set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AcmeContext" /> class.
    /// </summary>
    /// <param name="directoryUri">The directory URI.</param>
    /// <param name="accountKey">The account key.</param>
    /// <param name="http">The HTTP client.</param>
    /// <param name="badNonceRetryCount">The number of retries on a bad nonce.</param>
    /// <exception cref="ArgumentNullException">
    /// If <paramref name="directoryUri"/> is <c>null</c>.
    /// </exception>
    public AcmeContext(
        Uri directoryUri,
        IKey? accountKey = null,
        IAcmeHttpClient? http = null,
        int badNonceRetryCount = 1)
    {
        DirectoryUri = directoryUri ?? throw new ArgumentNullException(nameof(directoryUri));
        AccountKey = accountKey ?? KeyFactory.NewKey(DefaultKeyType);
        HttpClient = http ?? new AcmeHttpClient(directoryUri);
        BadNonceRetryCount = badNonceRetryCount;
    }

    /// <summary>
    /// Gets the ACME account context.
    /// </summary>
    /// <returns>The ACME account context.</returns>
    public async Task<IAccountContext> Account()
    {
        if (_accountContext != null)
        {
            return _accountContext;
        }

        var resp = await AccountContext.NewAccount(this, new Account.Payload { OnlyReturnExisting = true });
        return _accountContext = new AccountContext(this, resp.Location);
    }

    /// <summary>
    /// Changes the account key.
    /// </summary>
    /// <param name="key">The new account key.</param>
    /// <returns>The account resource.</returns>
    public async Task<Account> ChangeKey(IKey? key)
    {
        var endpoint = await this.GetResourceUri(d => d.KeyChange);
        var location = await Account().Location();

        var newKey = key ?? KeyFactory.NewKey(DefaultKeyType);
        var keyChange = new KeyChange
        {
            Account = location,
            OldKey = AccountKey.JsonWebKey,
        };

        var jws = new JwsSigner(newKey);
        var body = jws.Sign(keyChange, url: endpoint);

        var resp = await HttpClient.Post<Account, JwsPayload>(this, endpoint, body, true);

        AccountKey = newKey;
        return resp.Resource;
    }

    /// <summary>
    /// Creates the account.
    /// </summary>
    /// <returns>
    /// The account created.
    /// </returns>
    public async Task<IAccountContext> NewAccount(
        IList<string> contact,
        bool termsOfServiceAgreed,
        string? eabKeyId = null,
        string? eabKey = null,
        string? eabKeyAlg = null)
    {
        var body = new Account
        {
            Contact = contact,
            TermsOfServiceAgreed = termsOfServiceAgreed
        };

        var resp = await AccountContext.NewAccount(this, body, eabKeyId, eabKey, eabKeyAlg);
        return _accountContext = new AccountContext(this, resp.Location);
    }

    /// <summary>
    /// Gets the ACME directory.
    /// </summary>
    /// <returns>
    /// The ACME directory.
    /// </returns>
    public async Task<Directory> GetDirectory()
    {
        if (_directory == null)
        {
            var resp = await HttpClient.Get<Directory>(DirectoryUri);
            _directory = resp.Resource;
        }

        return _directory;
    }

    /// <summary>
    /// Revokes the certificate.
    /// </summary>
    /// <param name="certificate">The certificate in DER format.</param>
    /// <param name="reason">The reason for revocation.</param>
    /// <param name="certificatePrivateKey">The certificate's private key.</param>
    /// <returns>
    /// The awaitable.
    /// </returns>
    public async Task RevokeCertificate(
        Memory<byte> certificate,
        RevocationReason reason,
        IKey? certificatePrivateKey)
    {
        var endpoint = await this.GetResourceUri(d => d.RevokeCert);

        var body = new CertificateRevocation
        {
            Certificate = JwsConvert.ToBase64String(certificate),
            Reason = reason
        };

        if (certificatePrivateKey != null)
        {
            var jws = new JwsSigner(certificatePrivateKey);
            await HttpClient.Post<string, CertificateRevocation>(jws, endpoint, body);
        }
        else
        {
            await HttpClient.Post<string, CertificateRevocation>(this, endpoint, body);
        }
    }

    /// <summary>
    /// Creates a new the order.
    /// </summary>
    /// <param name="identifiers">The identifiers.</param>
    /// <param name="notBefore">Th value of not before field for the certificate.</param>
    /// <param name="notAfter">The value of not after field for the certificate.</param>
    /// <returns>
    /// The order context created.
    /// </returns>
    public async Task<IOrderContext> NewOrder(
        IList<string> identifiers,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        var endpoint = await this.GetResourceUri(d => d.NewOrder);

        var body = new Order
        {
            Identifiers = identifiers
                .Select(id => new Identifier { Type = IdentifierType.Dns, Value = id })
                .ToArray(),
            NotBefore = notBefore,
            NotAfter = notAfter,
        };

        var order = await HttpClient.Post<Order, Order>(this, endpoint, body, true);
        return new OrderContext(this, order.Location);
    }

    /// <summary>
    /// Signs the data with account key.
    /// </summary>
    /// <param name="entity">The data to sign.</param>
    /// <param name="uri">The URI for the request.</param>
    /// <returns>The JWS payload.</returns>
    public async Task<JwsPayload> Sign<T>(T? entity, Uri uri)
    {
        var nonce = await HttpClient.ConsumeNonce();
        var location = await Account().Location();
        var jws = new JwsSigner(AccountKey);
        return jws.Sign(entity, location, uri, nonce);
    }

    /// <summary>
    /// Gets the order by specified location.
    /// </summary>
    /// <param name="location">The order location.</param>
    /// <returns>
    /// The order context.
    /// </returns>
    public IOrderContext Order(Uri location)
        => new OrderContext(this, location);

    /// <summary>
    /// Gets the authorization by specified location.
    /// </summary>
    /// <param name="location">The authorization location.</param>
    /// <returns>
    /// The authorization context.
    /// </returns>
    public IAuthorizationContext Authorization(Uri location)
        => new AuthorizationContext(this, location);
}

internal class KeyChange
{
    public Uri Account { get; set; } = null!;

    public JsonWebKey OldKey { get; set; } = null!;
}
