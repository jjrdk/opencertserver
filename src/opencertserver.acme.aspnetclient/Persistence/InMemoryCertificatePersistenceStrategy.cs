namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

internal sealed class InMemoryCertificatePersistenceStrategy : ICertificatePersistenceStrategy
{
    private byte[]? _accountCertificate;
    private byte[]? _siteCertificate;

    public Task Persist(CertificateType persistenceType, byte[] certificate)
    {
        switch (persistenceType)
        {
            case CertificateType.Account:
                _accountCertificate = certificate;
                break;
            case CertificateType.Site:
                _siteCertificate = certificate;
                break;
            default:
                throw new ArgumentException("Unhandled persistence type", nameof(persistenceType));
        }

        return Task.CompletedTask;
    }

    public Task<byte[]?> RetrieveAccountCertificate()
    {
        return Task.FromResult(_accountCertificate);
    }

    public Task<X509Certificate2?> RetrieveSiteCertificate()
    {
        return Task.FromResult(_siteCertificate == null ? null :  X509CertificateLoader.LoadCertificate(_siteCertificate));
    }
}
