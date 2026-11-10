namespace OpenCertServer.Acme.Remote;

using System.Text;
using Acme.Abstractions.IssuanceServices;
using Ca.Utils.Ca;
using Ca.Utils.X509Extensions;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using OpenCertServer.Ca.Client;

/// <summary>
/// An ACME <see cref="IIssueCertificates"/> that delegates issuance to a backing certificate authority
/// over a trusted HTTPS connection via a <see cref="CaClient"/>. This is the ACME side of separating the
/// ACME server from the CA: the ACME host references this instead of the CA core, and the backing CA
/// stays authoritative for scope and identity. A success is returned as a PEM chain; a CA rejection is
/// surfaced as an <see cref="AcmeError"/> so the ACME order fails cleanly.
/// </summary>
public sealed class RemoteIssuer : IIssueCertificates
{
    private readonly CaClient _caClient;

    /// <summary>Creates a remote issuer backed by <paramref name="caClient"/>.</summary>
    public RemoteIssuer(CaClient caClient)
    {
        _caClient = caClient;
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

        // The requestor identity is not forwarded: the backing CA authenticates this ACME process over
        // the trusted connection (mTLS or bearer), and the delegated scope, when any, comes from the
        // client configuration.
        var response = await _caClient.SignCsr(
            csr,
            profile,
            notBefore: notBefore,
            notAfter: notAfter,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return response switch
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
