namespace OpenCertServer.Acme.AspNetClient
{
    using Certes;
    using Certificates;
    using Microsoft.AspNetCore.Server.Kestrel.Core;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;

    internal class KestrelOptionsSetup : IConfigureOptions<KestrelServerOptions>
    {
        private readonly ILogger<KestrelOptionsSetup> _logger;

        public KestrelOptionsSetup(ILogger<KestrelOptionsSetup> logger)
        {
            _logger = logger;
        }
        
        public void Configure(KestrelServerOptions options)
        {
            if (AcmeRenewalService.Certificate is LetsEncryptX509Certificate x509Certificate)
            {
                options.ConfigureHttpsDefaults(o =>
                {
                    o.ServerCertificateSelector = (_, _) => x509Certificate.GetCertificate();
                });
            }
            else if(AcmeRenewalService.Certificate != null)
            {
                _logger.LogError("This certificate cannot be used with Kestrel");
            }
        }
    }
}
