namespace OpenCertServer.Ca;

using System.Security.Cryptography.X509Certificates;

public interface IProvideRootCertificates
{
    X509Certificate2Collection GetRootCertificates();
}