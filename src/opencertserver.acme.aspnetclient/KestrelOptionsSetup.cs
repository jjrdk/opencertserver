namespace OpenCertServer.Acme.AspNetClient;

using Certes;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

internal sealed class KestrelOptionsSetup : IConfigureOptions<KestrelServerOptions>
{
    private readonly AcmeRenewalService _renewalService;
    private readonly ILogger<KestrelOptionsSetup> _logger;

    public KestrelOptionsSetup(AcmeRenewalService renewalService, ILogger<KestrelOptionsSetup> logger)
    {
        _renewalService = renewalService;
        _logger = logger;
    }

    public void Configure(KestrelServerOptions options)
    {
        if (_renewalService.Certificate != null)
        {
            options.ConfigureHttpsDefaults(o =>
            {
                o.ServerCertificateSelector = (_, _) => _renewalService.Certificate;
            });
        }
        else //if(AcmeRenewalService.Certificate != null)
        {
            _logger.LogError("This certificate cannot be used with Kestrel");
        }
    }
}