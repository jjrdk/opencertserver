using System.Text;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Utils;

namespace OpenCertServer.Lambda;

internal sealed class DefaultIssuer : ICertificateIssuer
{
    private readonly ICertificateAuthority _ca;

    public DefaultIssuer(ICertificateAuthority ca)
    {
        _ca = ca;
    }

    /// <inheritdoc />
    public async Task<(byte[]? certificate, AcmeError? error)> IssueCertificate(
        string csr,
        IEnumerable<Identifier> identifiers,
        CancellationToken cancellationToken)
    {
        await Task.Yield();

        var cert = _ca.SignCertificateRequest(csr);
        return cert switch
        {
            SignCertificateResponse.Success success => (
                Encoding.UTF8.GetBytes(success.Certificate.ToPemChain(success.Issuers)), null),
            SignCertificateResponse.Error error => (null, new AcmeError("multiple", string.Join(", ", error.Errors))),
            _ => throw new ArgumentException("Invalid response")
        };
    }
}
