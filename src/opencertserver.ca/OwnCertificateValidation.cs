namespace OpenCertServer.Ca
{
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using Microsoft.Extensions.Logging;
    using Utils;

    public class OwnCertificateValidation : IValidateCertificateRequests
    {
        private readonly X509Certificate2Collection _serverCertificates;
        private readonly ILogger<OwnCertificateValidation> _logger;

        public OwnCertificateValidation(X509Certificate2Collection serverCertificates, ILogger<OwnCertificateValidation> logger)
        {
            _serverCertificates = serverCertificates;
            _logger = logger;
        }

        public bool Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null)
        {
            var result = reenrollingFrom == null
                         || _serverCertificates.OfType<X509Certificate2>()
                             .Aggregate(false, (b, cert) => b || reenrollingFrom.IssuerName.Name == cert.SubjectName.Name);
            if (!result)
            {
                _logger.LogError($"Could not validate re-enrollment from {reenrollingFrom!.IssuerName.Name}");
            }

            return result;
        }
    }
}