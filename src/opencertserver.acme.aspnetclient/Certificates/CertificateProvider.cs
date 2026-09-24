using OpenCertServer.Acme.Abstractions.AcmeRoute;

namespace OpenCertServer.Acme.AspNetClient.Certificates;

using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Microsoft.Extensions.Logging;
using Persistence;

public sealed partial class CertificateProvider : IProvideCertificates
{
    private readonly IPersistenceService _persistenceService;
    private readonly IAcmeClientFactory _clientFactory;
    private readonly IValidateCertificates _certificateValidator;
    private readonly IDnsChallengeProvider _dnsChallengeProvider;
    private readonly AcmeOptions? _options;

    private readonly ILogger<CertificateProvider> _logger;

    /// <summary>
    /// Back-compatible constructor. Uses the in-process http-01 flow (the
    /// <c>AcmeChallengeApprovalMiddleware</c>) with a no-op DNS provider. Prefer the constructor
    /// that takes <see cref="IDnsChallengeProvider"/> and <see cref="AcmeOptions"/> to enable DNS-01.
    /// </summary>
    public CertificateProvider(
        IValidateCertificates certificateValidator,
        IPersistenceService persistenceService,
        IAcmeClientFactory clientFactory,
        ILogger<CertificateProvider> logger)
            : this(certificateValidator, persistenceService, clientFactory,
                NullDnsChallengeProvider.Instance, null, logger)
    {
    }

    public CertificateProvider(
        IValidateCertificates certificateValidator,
        IPersistenceService persistenceService,
        IAcmeClientFactory clientFactory,
        IDnsChallengeProvider dnsChallengeProvider,
        AcmeOptions? options,
        ILogger<CertificateProvider> logger)
    {
        _persistenceService = persistenceService;
        _clientFactory = clientFactory;
        _certificateValidator = certificateValidator;
        _dnsChallengeProvider = dnsChallengeProvider;
        _options = options;
        _logger = logger;
    }

    public Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        CancellationToken cancellationToken = default)
    {
        return RenewCertificateIfNeeded(password, null, null, cancellationToken);
    }

    public Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        X509Certificate2? current,
        CancellationToken cancellationToken = default)
    {
        return RenewCertificateIfNeeded(password, null, current, cancellationToken);
    }

    public Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        string? routeId,
        X509Certificate2? current = null,
        CancellationToken cancellationToken = default)
    {
        var scope = NormalizeRouteId(routeId);
        return RenewForRoute(password, scope, [], current, cancellationToken);
    }

    public Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        string? routeId,
        IReadOnlyList<string> hosts,
        X509Certificate2? current = null,
        CancellationToken cancellationToken = default)
    {
        var scope = NormalizeRouteId(routeId);
        return RenewForRoute(password, scope, hosts, current, cancellationToken);
    }

    private async Task<CertificateRenewalResult> RenewForRoute(
        string password,
        string scope,
        IReadOnlyList<string> hosts,
        X509Certificate2? current,
        CancellationToken cancellationToken)
    {
        LogCheckingToSeeIfInMemoryLetsencryptCertificateNeedsRenewal();
        if (_certificateValidator.IsCertificateValid(current))
        {
            LogCurrentInMemoryLetsencryptCertificateIsValid();
            return new CertificateRenewalResult(current, CertificateRenewalStatus.Unchanged);
        }

        LogCheckingToSeeIfExistingLetsencryptCertificateHasBeenPersistedAndIsValid();
        var persistedSiteCertificate = await GetPersisted(scope, cancellationToken).ConfigureAwait(false);
        if (_certificateValidator.IsCertificateValid(persistedSiteCertificate))
        {
            LogAPersistedNonExpiredLetsEncryptCertificateWasFoundAndWillBeUsedThumbprint(persistedSiteCertificate
                ?.Thumbprint);
            return new CertificateRenewalResult(persistedSiteCertificate, CertificateRenewalStatus.LoadedFromStore);
        }

        LogNoValidCertificateWasFoundRequestingNewCertificateFromLetsEncrypt();
        var newCertificate = await RequestNewLetsEncryptCertificate(password, scope, hosts, cancellationToken)
            .ConfigureAwait(false);
        return new CertificateRenewalResult(newCertificate, CertificateRenewalStatus.Renewed);
    }

    private Task<X509Certificate2?> GetPersisted(string scope, CancellationToken cancellationToken)
        => _persistenceService.GetPersistedSiteCertificate(scope, cancellationToken);

    private async Task<X509Certificate2?> RequestNewLetsEncryptCertificate(
        string password,
        string scope,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken)
    {
        var client = await _clientFactory.GetClient().ConfigureAwait(false);

        var orderDomains = hosts.Count > 0 ? [.. hosts] : Array.Empty<string>();
        var challengeType = _options?.ChallengeType ?? ChallengeType.Http01;
        var placedOrder =
            await client.PlaceOrder(challengeType, orderDomains).ConfigureAwait(false);

        await _persistenceService.PersistChallenges(placedOrder.Challenges).ConfigureAwait(false);

        var existingKeyPem =
            await _persistenceService.GetPersistedRouteKey(scope, cancellationToken).ConfigureAwait(false);

        // DNS-01 challenges are not answered in-process (the http-01 approval middleware does not
        // apply). The TXT record must be written into the DNS zone by a registered provider before
        // the ACME server validates, and removed afterwards. For http-01 this block is skipped, so
        // the existing flow is unchanged.
        var dnsRecords = challengeType == ChallengeType.Dns01
             ? placedOrder.Challenges
                  .Select(DnsRecordFor)
                  .Where(r => r is not null)
                  .Select(r => (DnsChallengeRecord)r!)
                  .Distinct()
                  .ToArray()
             : [];

        try
        {
            if (dnsRecords.Length > 0)
            {
                await _dnsChallengeProvider.PlaceChallengesAsync(dnsRecords, cancellationToken)
                      .ConfigureAwait(false);
            }

            var (certificate, usedKeyPem, collection) =
                await client.FinalizeOrder(placedOrder, password, existingKeyPem).ConfigureAwait(false);

            await _persistenceService.PersistSiteCertificateChain(collection, scope, cancellationToken)
                  .ConfigureAwait(false);
            await _persistenceService.PersistRouteKey(scope, usedKeyPem, cancellationToken)
                  .ConfigureAwait(false);

            return certificate;
        }
        catch (TaskCanceledException canceled)
        {
            LogCancelledPersistingSiteCertificate(canceled);
            return null;
        }
        finally
        {
            if (dnsRecords.Length > 0)
            {
                await _dnsChallengeProvider.RemoveChallengesAsync(dnsRecords, cancellationToken)
                      .ConfigureAwait(false);
            }

            await _persistenceService.DeleteChallenges(placedOrder.Challenges).ConfigureAwait(false);
        }
    }

    // For DNS-01 the TXT record is published at _acme-challenge.<identifier> carrying the base64
    // key-authentication digest that AcmeClient stored in the challenge's Token field. A
    // challenge's Domains lists the order identifiers; the first one is used to derive the record
    // name, mirroring how the http-01 path keys off the first identifier. A wildcard identifier
    // keeps its star prefix stripped so the zone writes _acme-challenge.<example.com> for
    // *.example.com, which is the name the ACME RFC requires for wildcards.
    private static DnsChallengeRecord? DnsRecordFor(ChallengeDto challenge)
    {
        var domain = challenge.Domains is { Length: > 0 } ? challenge.Domains[0] : null;
        if (string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        var name = domain.StartsWith("*.", StringComparison.Ordinal)
             ? $"_acme-challenge.{domain[2..]}"
             : $"_acme-challenge.{domain}";

        return new DnsChallengeRecord(name, challenge.Token);
    }

    private static string NormalizeRouteId(string? routeId)
    {
        return string.IsNullOrEmpty(routeId) ? AcmeRouteConstants.DefaultRouteId : routeId;
    }

    [LoggerMessage(LogLevel.Information, "Checking to see if in-memory LetsEncrypt certificate needs renewal")]
    partial void LogCheckingToSeeIfInMemoryLetsencryptCertificateNeedsRenewal();

    [LoggerMessage(LogLevel.Information, "Current in-memory LetsEncrypt certificate is valid")]
    partial void LogCurrentInMemoryLetsencryptCertificateIsValid();

    [LoggerMessage(LogLevel.Information,
        "Checking to see if existing LetsEncrypt certificate has been persisted and is valid")]
    partial void LogCheckingToSeeIfExistingLetsencryptCertificateHasBeenPersistedAndIsValid();

    [LoggerMessage(LogLevel.Information,
        "A persisted non-expired LetsEncrypt certificate was found and will be used: {Thumbprint}")]
    partial void LogAPersistedNonExpiredLetsEncryptCertificateWasFoundAndWillBeUsedThumbprint(string? thumbprint);

    [LoggerMessage(LogLevel.Information, "No valid certificate was found. Requesting new certificate from LetsEncrypt")]
    partial void LogNoValidCertificateWasFoundRequestingNewCertificateFromLetsEncrypt();

    [LoggerMessage(LogLevel.Error, "Cancelled persisting site certificate")]
    partial void LogCancelledPersistingSiteCertificate(Exception exception);
}
