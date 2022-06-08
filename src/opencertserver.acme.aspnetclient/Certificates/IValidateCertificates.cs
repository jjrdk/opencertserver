namespace OpenCertServer.Acme.AspNetClient.Certificates;

using System.Security.Cryptography.X509Certificates;

public interface IValidateCertificates
{
    bool IsCertificateValid(X509Certificate2? certificate);
}