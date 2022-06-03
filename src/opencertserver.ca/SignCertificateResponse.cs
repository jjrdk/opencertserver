namespace OpenCertServer.Ca
{
    using System.Security.Cryptography.X509Certificates;

    public abstract class SignCertificateResponse
    {
        public class Success : SignCertificateResponse
        {
            internal Success(X509Certificate2 certificate, X509Certificate2Collection issuers)
            {
                Certificate = certificate;
                Issuers = issuers;
            }

            public X509Certificate2 Certificate { get; }

            public X509Certificate2Collection Issuers { get; }
        }

        public class Error : SignCertificateResponse
        {
            internal Error(params string[] errors)
            {
                Errors = errors;
            }

            public string[] Errors { get; }
        }
    }
}