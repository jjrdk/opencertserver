namespace OpenCertServer.Acme.AspNetClient.Certificates;

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Certes;
using Microsoft.Extensions.Logging;
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

    public async Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        X509Certificate2? current = null,
        CancellationToken cancellationToken = default)
    {
        LogCheckingToSeeIfInMemoryLetsencryptCertificateNeedsRenewal();
        if (_certificateValidator.IsCertificateValid(current))
        {
            LogCurrentInMemoryLetsencryptCertificateIsValid();
            return new CertificateRenewalResult(current, CertificateRenewalStatus.Unchanged);
        }

        LogCheckingToSeeIfExistingLetsencryptCertificateHasBeenPersistedAndIsValid();
        var persistedSiteCertificate = await _persistenceService.GetPersistedSiteCertificate(cancellationToken);
        if (_certificateValidator.IsCertificateValid(persistedSiteCertificate))
        {
            LogAPersistedNonExpiredLetsEncryptCertificateWasFoundAndWillBeUsedThumbprint(persistedSiteCertificate?.Thumbprint);
            return new CertificateRenewalResult(persistedSiteCertificate, CertificateRenewalStatus.LoadedFromStore);
        }

        LogNoValidCertificateWasFoundRequestingNewCertificateFromLetsEncrypt();
        var newCertificate = await RequestNewLetsEncryptCertificate(password, cancellationToken);
        return new CertificateRenewalResult(newCertificate, CertificateRenewalStatus.Renewed);
    }

    private async Task<X509Certificate2?> RequestNewLetsEncryptCertificate(
        string password,
        CancellationToken cancellationToken)
    {
        var client = await _clientFactory.GetClient();

        var placedOrder = await client.PlaceOrder();

        await _persistenceService.PersistChallenges(placedOrder.Challenges);

        try
        {
            var pfxCertificateBytes = await client.FinalizeOrder(placedOrder, password);

            await _persistenceService.PersistSiteCertificate(pfxCertificateBytes, cancellationToken);

            return  X509CertificateLoader.LoadCertificate(pfxCertificateBytes.RawData);
        }
        catch (TaskCanceledException canceled)
        {
            LogCancelledPersistingSiteCertificate(canceled);
            return null;
        }
        finally
        {
            await _persistenceService.DeleteChallenges(placedOrder.Challenges);
        }
    }

    [LoggerMessage(LogLevel.Information, "Checking to see if in-memory LetsEncrypt certificate needs renewal")]
    partial void LogCheckingToSeeIfInMemoryLetsencryptCertificateNeedsRenewal();

    [LoggerMessage(LogLevel.Information, "Current in-memory LetsEncrypt certificate is valid")]
    partial void LogCurrentInMemoryLetsencryptCertificateIsValid();

    [LoggerMessage(LogLevel.Information, "Checking to see if existing LetsEncrypt certificate has been persisted and is valid")]
    partial void LogCheckingToSeeIfExistingLetsencryptCertificateHasBeenPersistedAndIsValid();

    [LoggerMessage(LogLevel.Information, "A persisted non-expired LetsEncrypt certificate was found and will be used: {Thumbprint}")]
    partial void LogAPersistedNonExpiredLetsEncryptCertificateWasFoundAndWillBeUsedThumbprint(string? thumbprint);

    [LoggerMessage(LogLevel.Information, "No valid certificate was found. Requesting new certificate from LetsEncrypt")]
    partial void LogNoValidCertificateWasFoundRequestingNewCertificateFromLetsEncrypt();

    [LoggerMessage(LogLevel.Error, "Cancelled persisting site certificate")]
    partial void LogCancelledPersistingSiteCertificate(Exception exception);
}
