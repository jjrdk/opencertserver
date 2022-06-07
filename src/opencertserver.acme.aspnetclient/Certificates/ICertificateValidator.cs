namespace OpenCertServer.Acme.AspNetClient.Certificates;

using System.Security.Cryptography.X509Certificates;

public interface ICertificateValidator
{
    bool IsCertificateValid(X509Certificate2? certificate);
}