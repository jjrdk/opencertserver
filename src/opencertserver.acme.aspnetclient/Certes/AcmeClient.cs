namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CertesSlim;
using CertesSlim.Extensions;
using Exceptions;
using global::CertesSlim.Acme;
using global::CertesSlim.Acme.Resource;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Persistence;

public enum ChallengeType
{
    Http01,
    Dns01
}

public sealed partial class AcmeClient : IAcmeClient
{
    private readonly ILogger _logger;
    private readonly IAcmeContext _acme;
    private readonly AcmeOptions _options;

    public AcmeClient(IAcmeContext acme, AcmeOptions options, ILogger logger)
    {
        _logger = logger;
        _acme = acme;
        _options = options;
    }

    public async Task<PlacedOrder> PlaceOrder(ChallengeType challengeType, string[] domains)
    {
        LogOrderingLetsEncryptCertificateForDomainsDomains(string.Join(", ", domains));
        var order = await _acme.NewOrder(_options.Profile, domains).ConfigureAwait(false);

        var allAuthorizations = await order.Authorizations().ConfigureAwait(false);

        var challengeContexts = (await Task.WhenAll(
                allAuthorizations.Select(x => challengeType == ChallengeType.Dns01 ? x.Dns() : x.Http())).ConfigureAwait(false))
            .Where(x => x != null)
            .Cast<IChallengeContext>()
            .ToArray();

        var dtos = challengeContexts.Select(x => new ChallengeDto(
                x.Type == ChallengeTypes.Dns01 ? _acme.AccountKey.DnsTxt(x.Token) : x.Token,
                x.KeyAuthz,
                domains))
            .ToArray();

        LogAcmePlacedOrderForDomainsDomainsWithChallengesChallenges(domains, dtos);

        return new PlacedOrder(dtos, order, challengeContexts);
    }

    public async Task<(X509Certificate2 Certificate, string KeyPem, X509Certificate2Collection Collection)>
        FinalizeOrder(
        PlacedOrder placedOrder,
        string password,
        string? existingKeyPem = null)
    {
        await ValidateChallenges(placedOrder.ChallengeContexts).ConfigureAwait(false);

        LogAcquiringCertificateThroughSigningRequest();

        var keyPair = existingKeyPem != null
            ? KeyFactory.FromPem(existingKeyPem)
            : KeyFactory.NewKey(_options.KeyAlgorithm);

        var certificateChain =
            await placedOrder.Order.Generate(_options.CertificateSigningRequest, keyPair, retryCount: 10)
                .ConfigureAwait(false);

        // CertificateChain.Certificate is created from the PEM downloaded from the ACME server
        // and therefore has NO private key associated. We must combine it with the key pair used
        // to sign the CSR so that the resulting X509Certificate2 actually carries the private key,
        // otherwise HasPrivateKey is false and Kestrel throws:
        //    "The server mode SSL must use a certificate with the associated private key."
        //
        // Do NOT round-trip this leaf through a password-protected PKCS12 and load it back: on
        // Apple (macOS) the key is then pinned in the keychain and can no longer be exported, so
        // the persistence layer's leaf.Export(Pkcs12, string.Empty) and the key-PEM export throw
        // AppleCommonCryptoCryptographicException "The contents of this item cannot be
        // retrieved." The CreateFromPem object is already a self-contained, exportable cert+key.

        var leafWithKey = keyPair.SecurityKey switch
        {
            RsaSecurityKey rsaKey => certificateChain.Certificate.CopyWithPrivateKey(rsaKey.Rsa),
            ECDsaSecurityKey ecdsaKey => certificateChain.Certificate.CopyWithPrivateKey(ecdsaKey.ECDsa),
            _ => throw new NotSupportedException(
                $"Unsupported key type {keyPair.SecurityKey.GetType().FullName}")
        };

        LogCertificateAcquired();

        // The collection handed to persistence: the leaf (with its private key) first, followed by
        // the public issuer certificates so chains/server.crt holds the real chain rather than a
        // duplicate of the leaf.
        var chain = new X509Certificate2Collection { leafWithKey };
        foreach (var issuer in certificateChain.Issuers)
        {
            chain.Add(issuer);
        }

        return (leafWithKey, keyPair.ToPem(), chain);
    }

    private async Task ValidateChallenges(IChallengeContext[] challengeContexts)
    {
        LogValidatingAllPendingOrderAuthorizations();

        var challengeValidationResponses = await InnerValidateChallenges(challengeContexts).ConfigureAwait(false);

        var challengeExceptions = challengeValidationResponses.Where(x => x.Status == ChallengeStatus.Invalid)
            .Select(x => new Exception(
                $"{x.Error?.Type ?? "error type null"}: {x.Error?.Detail ?? "null error details"} (challenge type {x.Type ?? "null"})"))
            .ToArray();

        if (challengeExceptions.Length > 0)
        {
            throw new OrderInvalidException(
                "One or more LetsEncrypt orders were invalid. Make sure that LetsEncrypt can contact the domain you are trying to request an SSL certificate for, in order to verify it.",
                new AggregateException(challengeExceptions));
        }
    }

    private static async Task<Challenge[]> InnerValidateChallenges(IChallengeContext[] challengeContexts)
    {
        var challenges = await Task.WhenAll(challengeContexts.Select(x => x.Validate())).ConfigureAwait(false);

        while (true)
        {
            var allValid = challenges.All(x => x.Status == ChallengeStatus.Valid);
            var anyInvalid = challenges.Any(x => x.Status == ChallengeStatus.Invalid);

            if (allValid || anyInvalid)
            {
                break;
            }

            challenges = await Task.WhenAll(challengeContexts.Select(x => x.Resource())).ConfigureAwait(false);
        }

        return challenges;
    }

    [LoggerMessage(LogLevel.Information, "Ordering LetsEncrypt certificate for domains {Domains}")]
    partial void LogOrderingLetsEncryptCertificateForDomainsDomains(string domains);

    [LoggerMessage(LogLevel.Trace, "Acme placed order for domains {Domains} with challenges {Challenges}")]
    partial void LogAcmePlacedOrderForDomainsDomainsWithChallengesChallenges(
        string[] domains,
        ChallengeDto[] challenges);

    [LoggerMessage(LogLevel.Information, "Acquiring certificate through signing request")]
    partial void LogAcquiringCertificateThroughSigningRequest();

    [LoggerMessage(LogLevel.Information, "Certificate acquired")]
    partial void LogCertificateAcquired();

    [LoggerMessage(LogLevel.Information, "Validating all pending order authorizations")]
    partial void LogValidatingAllPendingOrderAuthorizations();
}
