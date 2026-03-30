using System.Security.Claims;
using System.Text;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509Extensions;

namespace OpenCertServer.Lambda;

internal sealed class DefaultIssuer : IIssueCertificates
{
    private readonly ICertificateAuthority _ca;

    public DefaultIssuer(ICertificateAuthority ca)
    {
        _ca = ca;
    }

    /// <inheritdoc />
    public async Task<(byte[]? certificate, AcmeError? error)> IssueCertificate(
        string? profile,
        string csr,
        IEnumerable<Identifier> identifiers,
        CancellationToken cancellationToken)
    {
        await Task.Yield();

        var cert = await _ca.SignCertificateRequestPem(
            csr,
            profile,
            new ClaimsIdentity(identifiers.Select(i => new Claim(i.Type, i.Value)), "acme"), cancellationToken: cancellationToken);
        return cert switch
        {
            SignCertificateResponse.Success success => (
                Encoding.UTF8.GetBytes(success.Certificate.ToPemChain(success.Issuers)), null),
            SignCertificateResponse.Error error => (null, new AcmeError("multiple", string.Join(", ", error.Errors))),
            _ => throw new ArgumentException("Invalid response")
        };
    }
}
