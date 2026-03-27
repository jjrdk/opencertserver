using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.CertServer;

using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509Extensions;
using System.Text;
using Acme.Abstractions.IssuanceServices;
using Acme.Abstractions.Model;

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
        cancellationToken.ThrowIfCancellationRequested();
        var cert = _ca.SignCertificateRequestPem(
            csr,
            profile,
            new System.Security.Claims.ClaimsIdentity(
                identifiers.Select(i => new System.Security.Claims.Claim(i.Type, i.Value)), "acme"));
        return cert switch
        {
            SignCertificateResponse.Success success => (
                Encoding.UTF8.GetBytes(success.Certificate.ToPemChain(success.Issuers)), null),
            SignCertificateResponse.Error error => (null, new AcmeError("multiple", string.Join(", ", error.Errors))),
            _ => throw new ArgumentException("Invalid response")
        };
    }
}
