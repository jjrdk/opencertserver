namespace OpenCertServer.Ca
{
    using System.Security.Cryptography.X509Certificates;

    public abstract class SignCertificateResponse
    {
        public class Success : SignCertificateResponse
        {
            internal Success(X509Certificate2 certificate)
            {
                Certificate = certificate;
            }

            public X509Certificate2 Certificate { get; }
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