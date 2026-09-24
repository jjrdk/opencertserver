using CertesSlim.Acme;

namespace OpenCertServer.CertServer;

using System.Text;
using Acme.Abstractions.IssuanceServices;
using Ca.Utils.X509Extensions;
using CertesSlim.Acme.Resource;
using OpenCertServer.Ca.Utils.Ca;

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
        DateTimeOffset? notBefore,
        DateTimeOffset? notAfter,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();
        var cert = await _ca.SignCertificateRequestPem(
            csr,
            profile,
            new System.Security.Claims.ClaimsIdentity(
                identifiers.Select(i =>
                    new System.Security.Claims.Claim(i.Type.ToString().ToLowerInvariant(), i.Value)), "acme"),
            notBefore: notBefore,
            notAfter: notAfter,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return cert switch
        {
            SignCertificateResponse.Success success => (
                Encoding.UTF8.GetBytes(success.Certificate.ToPemChain(success.Issuers)), null),
            SignCertificateResponse.Error error => (null, new AcmeError
            {
                Type = "multiple",
                Detail = string.Join(", ", error.Errors)
            }),
            _ => throw new ArgumentException("Invalid response")
        };
    }
}
