namespace OpenCertServer.Acme.AspNetClient.Certificates;

public interface ICertificateValidator
{
    bool IsCertificateValid(IAbstractCertificate? certificate);
}