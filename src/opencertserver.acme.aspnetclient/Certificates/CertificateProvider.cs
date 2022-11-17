namespace OpenCertServer.Acme.AspNetClient.Certificates;

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Certes;
using Microsoft.Extensions.Logging;
using Persistence;

public sealed class CertificateProvider : IProvideCertificates
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
        _logger.LogInformation("Checking to see if in-memory LetsEncrypt certificate needs renewal.");
        if (_certificateValidator.IsCertificateValid(current))
        {
            _logger.LogInformation("Current in-memory LetsEncrypt certificate is valid.");
            return new CertificateRenewalResult(current, CertificateRenewalStatus.Unchanged);
        }

        _logger.LogInformation("Checking to see if existing LetsEncrypt certificate has been persisted and is valid.");
        var persistedSiteCertificate = await _persistenceService.GetPersistedSiteCertificate(cancellationToken);
        if (_certificateValidator.IsCertificateValid(persistedSiteCertificate))
        {
            _logger.LogInformation("A persisted non-expired LetsEncrypt certificate was found and will be used: {Thumbprint}", persistedSiteCertificate?.Thumbprint);
            return new CertificateRenewalResult(persistedSiteCertificate, CertificateRenewalStatus.LoadedFromStore);
        }

        _logger.LogInformation("No valid certificate was found. Requesting new certificate from LetsEncrypt.");
        var newCertificate = await RequestNewLetsEncryptCertificate(password, cancellationToken);
        return new CertificateRenewalResult(newCertificate, CertificateRenewalStatus.Renewed);
    }

    private async Task<X509Certificate2?> RequestNewLetsEncryptCertificate(string password, CancellationToken cancellationToken)
    {
        var client = await _clientFactory.GetClient();

        var placedOrder = await client.PlaceOrder();

        await _persistenceService.PersistChallenges(placedOrder.Challenges);

        try
        {
            var pfxCertificateBytes = await client.FinalizeOrder(placedOrder, password);

            await _persistenceService.PersistSiteCertificate(pfxCertificateBytes, cancellationToken);

            return new X509Certificate2(pfxCertificateBytes.RawData);
        }
        catch (TaskCanceledException canceled)
        {
            _logger.LogError(canceled, "Cancelled persisting site certificate");
            return null;
        }
        finally
        {
            await _persistenceService.DeleteChallenges(placedOrder.Challenges);
        }
    }
}