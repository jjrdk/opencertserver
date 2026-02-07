namespace OpenCertServer.Ca.Utils.Ca;

using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;

public abstract class SignCertificateResponse
{
    public sealed class Success : SignCertificateResponse
    {
        public Success(X509Certificate2 certificate, X509Certificate2Collection issuers)
        {
            Certificate = certificate;
            Issuers = issuers;
        }

        public X509Certificate2 Certificate { get; }

        public X509Certificate2Collection Issuers { get; }
    }

    public sealed class Error : SignCertificateResponse
    {
        public Error(params Span<string> errors)
        {
            Errors = [..errors];
        }

        public ImmutableArray<string> Errors { get; }
    }
}
