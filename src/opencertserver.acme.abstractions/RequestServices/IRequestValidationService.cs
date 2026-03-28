using CertesSlim.Json;

namespace OpenCertServer.Acme.Abstractions.RequestServices;

using System.Threading;
using System.Threading.Tasks;
using HttpModel.Requests;

/// <summary>
/// Defines a service for validating ACME protocol requests, including JWS payload and header validation.
/// </summary>
public interface IRequestValidationService
{
    /// <summary>
    /// Validates an incoming ACME request asynchronously, including payload, header, and request URL.
    /// </summary>
    /// <param name="request">The JWS payload of the request.</param>
    /// <param name="header">The ACME request header.</param>
    /// <param name="requestUrl">The URL to which the request was sent.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task representing the asynchronous validation operation.</returns>
    Task ValidateRequestAsync(
        JwsPayload request,
        AcmeHeader header,
        string requestUrl,
        CancellationToken cancellationToken);
}
