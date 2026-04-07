namespace OpenCertServer.Acme.Abstractions.Services;

using System.Threading;
using System.Threading.Tasks;
using HttpModel.Requests;

/// <summary>
/// Handles RFC 8555 certificate revocation requests.
/// </summary>
public interface IRevocationService
{
    /// <summary>
    /// Validates authorization for and revokes the submitted certificate.
    /// </summary>
    Task RevokeCertificate(AcmeHeader header, RevokeCertificateRequest request, CancellationToken cancellationToken);
}

