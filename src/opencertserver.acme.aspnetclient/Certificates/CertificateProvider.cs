namespace OpenCertServer.Acme.AspNetClient.Certificates;

using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Microsoft.Extensions.Logging;
using OpenCertServer.Acme.Abstractions.Acme;
using Persistence;

public sealed partial class CertificateProvider : IProvideCertificates
{
    private readonly IPersistenceService _persistenceService;
    private readonly IAcmeClientFactory _clientFactory;
    private readonly IValidateCertificates _certificateValidator;

    private readonly ILogger<CertificateProvider> _logger;

    public CertificateProvider(
        IValidateCertificates certificateValidator,
        IPersistenceService persistenceService,
        IAcmeClientFactory clientFactory,
        ILogger<CertificateProvider> logger)
        {
         _persistenceService = persistenceService;
         _clientFactory = clientFactory;
         _certificateValidator = certificateValidator;
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
                    ? .Thumbprint);
             return new CertificateRenewalResult(persistedSiteCertificate, CertificateRenewalStatus.LoadedFromStore);
              }

          LogNoValidCertificateWasFoundRequestingNewCertificateFromLetsEncrypt();
          var newCertificate = await RequestNewLetsEncryptCertificate(password, scope, hosts, cancellationToken).ConfigureAwait(false);
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
              var placedOrder = await client.PlaceOrder(orderDomains).ConfigureAwait(false);

             await _persistenceService.PersistChallenges(placedOrder.Challenges).ConfigureAwait(false);

             var existingKeyPem = await _persistenceService.GetPersistedRouteKey(scope, cancellationToken).ConfigureAwait(false);

             try
                   {
              var (certificate, usedKeyPem, collection) = await client.FinalizeOrder(placedOrder, password, existingKeyPem).ConfigureAwait(false);

              await _persistenceService.PersistSiteCertificateChain(collection, scope, cancellationToken).ConfigureAwait(false);
              await _persistenceService.PersistRouteKey(scope, usedKeyPem, cancellationToken).ConfigureAwait(false);

                     return certificate;
                      }
             catch (TaskCanceledException canceled)
                 {
                LogCancelledPersistingSiteCertificate(canceled);
                return null;
                    }
             finally
                 {
                await _persistenceService.DeleteChallenges(placedOrder.Challenges).ConfigureAwait(false);
                    }
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
