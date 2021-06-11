namespace OpenCertServer.Ca
{
    using System;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using Utils;

    public class DistinguishedNameValidation : IValidateCertificateRequests
    {
        public bool Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null)
        {
            return request.SubjectName.Format(true)
                .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                .Any(x => x.StartsWith("CN="));
        }
    }
}
