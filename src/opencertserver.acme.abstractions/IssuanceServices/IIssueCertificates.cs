namespace OpenCertServer.Acme.Abstractions.IssuanceServices;

using System.Threading;
using System.Threading.Tasks;
using Model;

public interface IIssueCertificates
{
    Task<(byte[]? certificate, AcmeError? error)> IssueCertificate(
        string csr,
        IEnumerable<Identifier> identifiers,
        CancellationToken cancellationToken);
}
