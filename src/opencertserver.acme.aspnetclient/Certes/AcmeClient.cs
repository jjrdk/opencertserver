using CertesSlim.Extensions;

namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CertesSlim;
using Exceptions;
using global::CertesSlim.Acme;
using global::CertesSlim.Acme.Resource;
using Microsoft.Extensions.Logging;
using Persistence;

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

    public async Task<PlacedOrder> PlaceOrder(params string[] domains)
    {
        LogOrderingLetsEncryptCertificateForDomainsDomains(string.Join(", ", domains));
        var order = await _acme.NewOrder(domains);

        var allAuthorizations = await order.Authorizations();

        var challengeContexts = (await Task.WhenAll(
            allAuthorizations.Select(x => x.Http()))).Where(x => x != null).Select(x => x!).ToArray();

        var dtos = challengeContexts.Select(x => new ChallengeDto(
                x.Type == ChallengeTypes.Dns01 ? _acme.AccountKey.DnsTxt(x.Token) ?? "" : x.Token,
                x.KeyAuthz,
                domains))
            .ToArray();

        LogAcmePlacedOrderForDomainsDomainsWithChallengesChallenges(domains, dtos);

        return new PlacedOrder(dtos, order, challengeContexts);
    }

    public async Task<X509Certificate2> FinalizeOrder(PlacedOrder placedOrder, string password)
    {
        await ValidateChallenges(placedOrder.ChallengeContexts);

        LogAcquiringCertificateThroughSigningRequest();

        var keyPair = KeyFactory.NewKey(_options.KeyAlgorithm);

        var certificateChain =
            await placedOrder.Order.Generate(_options.CertificateSigningRequest, keyPair, retryCount: 10);
        var collection = new X509Certificate2Collection { certificateChain.Certificate };
        foreach (var cert in certificateChain.Issuers)
        {
            collection.Add(cert);
        }

        var pfxBytes =
            collection.ExportPkcs12(Pkcs12ExportPbeParameters.Default, password);
        LogCertificateAcquired();

        return X509CertificateLoader.LoadPkcs12(pfxBytes, null);
    }

    private async Task ValidateChallenges(IChallengeContext[] challengeContexts)
    {
        LogValidatingAllPendingOrderAuthorizations();

        var challengeValidationResponses = await InnerValidateChallenges(challengeContexts);

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
        var challenges = await Task.WhenAll(challengeContexts.Select(x => x.Validate()));

        while (true)
        {
            var allValid = challenges.All(x => x.Status == ChallengeStatus.Valid);
            var anyInvalid = challenges.Any(x => x.Status == ChallengeStatus.Invalid);

            if (allValid || anyInvalid)
            {
                break;
            }

            await Task.Delay(1000);
            challenges = await Task.WhenAll(challengeContexts.Select(x => x.Resource()));
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
