namespace OpenCertServer.Est.Tests.Configuration
{
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication.Certificate;
    using Microsoft.Extensions.Options;

    public sealed class ConfigureCertificateAuthenticationOptions : IPostConfigureOptions<CertificateAuthenticationOptions>
    {
        private readonly X509Certificate2Collection _certificate2Collection;

        public ConfigureCertificateAuthenticationOptions(X509Certificate2Collection certificate2Collection)
        {
            _certificate2Collection = certificate2Collection;
        }

        public void PostConfigure(string? name, CertificateAuthenticationOptions options)
        {
            options.CustomTrustStore = _certificate2Collection;
            options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
            options.AllowedCertificateTypes = CertificateTypes.All;
            options.RevocationFlag = X509RevocationFlag.EndCertificateOnly;
            options.RevocationMode = X509RevocationMode.Offline;
            options.ValidateCertificateUse = false;
            options.ValidateValidityPeriod = false;
            options.Events = new CertificateAuthenticationEvents
            {
                OnChallenge = ctx =>
                {
                    ctx.HandleResponse();
                    return Task.CompletedTask;
                },
                OnCertificateValidated = _ => Task.CompletedTask,
                OnAuthenticationFailed = _ => Task.CompletedTask
            };
        }
    }
}
