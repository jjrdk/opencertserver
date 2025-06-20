namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Exceptions;
using global::Certes;
using global::Certes.Acme;
using global::Certes.Acme.Resource;
using Microsoft.Extensions.Logging;
using Persistence;

public sealed class AcmeClient : IAcmeClient
{
    private const string CertificateFriendlyName = "OpenCertServerAcmeCertificate";

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
        _logger.LogInformation("Ordering LetsEncrypt certificate for domains {domains}", string.Join(", ", domains));
        var order = await _acme.NewOrder(domains);

        var allAuthorizations = await order.Authorizations();

        var challengeContexts = await Task.WhenAll(
            (allAuthorizations ?? []).Select(x => x.Http()));
        var nonNullChallengeContexts = challengeContexts.Where(x => x != null).ToArray();

        var dtos = nonNullChallengeContexts.Select(x => new ChallengeDto(
                x.Type == ChallengeTypes.Dns01 ? _acme.AccountKey.DnsTxt(x.Token) ?? "" : x.Token,
                x.KeyAuthz,
                domains))
            .ToArray();

        _logger.LogTrace(
            "Acme placed order for domains {Domains} with challenges {Challenges}",
            domains,
            dtos);

        return new PlacedOrder(dtos, order, nonNullChallengeContexts);
    }

    public async Task<X509Certificate2> FinalizeOrder(PlacedOrder placedOrder, string password)
    {
        await ValidateChallenges(placedOrder.ChallengeContexts);

        _logger.LogInformation("Acquiring certificate through signing request");

        var keyPair = KeyFactory.NewKey(_options.KeyAlgorithm);

        var certificateChain =
            await placedOrder.Order.Generate(_options.CertificateSigningRequest, keyPair, retryCount: 10);

        var pfxBuilder = certificateChain.ToPfx(keyPair);

        pfxBuilder.FullChain = true;

        var pfxBytes = pfxBuilder.Build(CertificateFriendlyName, password);

        _logger.LogInformation("Certificate acquired");

#if NET8_0
        return new X509Certificate2(pfxBytes.AsSpan(), null);
#else
        return X509CertificateLoader.LoadPkcs12(pfxBytes, null);
#endif
    }

    private async Task ValidateChallenges(IChallengeContext[] challengeContexts)
    {
        _logger.LogInformation("Validating all pending order authorizations");

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
}
