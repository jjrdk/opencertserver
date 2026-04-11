namespace OpenCertServer.Acme.Abstractions.Services;

using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Defines a service that validates the <c>externalAccountBinding</c> JWS object in a
/// new-account request (RFC 8555 §7.3.4) and marks the provisioned key as used.
/// </summary>
public interface IExternalAccountBindingService
{
    /// <summary>
    /// Validates the external account binding JWS supplied in a new-account request.
    /// </summary>
    /// <param name="eabJws">
    /// The flattened JWS JSON object carried in the <c>externalAccountBinding</c> field
    /// of the new-account payload.
    /// </param>
    /// <param name="accountJwk">
    /// The account public key (the JWK from the outer new-account request's protected header).
    /// The EAB payload must equal this key, verifying ownership.
    /// </param>
    /// <param name="requestUrl">
    /// The URL of the new-account endpoint.
    /// The EAB protected header's <c>url</c> claim must match this value exactly.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The <c>kid</c> (external account key identifier) confirmed by the binding.</returns>
    /// <exception cref="Exceptions.ExternalAccountBindingException">
    /// Thrown when the EAB JWS is structurally invalid, the HMAC signature does not verify,
    /// the URL claim does not match, the payload does not contain the expected account key,
    /// or the external account key has already been used.
    /// </exception>
    Task<string> ValidateAsync(
        JsonElement eabJws,
        JsonWebKey accountJwk,
        string requestUrl,
        CancellationToken cancellationToken);

    /// <summary>
    /// Checks whether an active (unused) external account key with the given identifier exists.
    /// </summary>
    /// <param name="keyId">The external account key identifier to look up.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><c>true</c> when the key exists and has not yet been consumed; otherwise <c>false</c>.</returns>
    Task<bool> HasActiveKeyAsync(string keyId, CancellationToken cancellationToken);
}

