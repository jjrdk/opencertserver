namespace OpenCertServer.Acme.Abstractions.Services;

using CertesSlim.Acme.Resource;

/// <summary>
/// Defines the policy used to decide whether the CA is willing to issue a certificate
/// for a requested identifier submitted in an ACME new-order request.
/// </summary>
public interface IAllowedIdentifiersPolicy
{
    /// <summary>
    /// Determines whether the specified identifier is allowed, returning the reason it
    /// was rejected when it is not.
    /// </summary>
    /// <param name="identifier">The identifier being validated.</param>
    /// <returns>
    /// <c>null</c> when the identifier is allowed, or a non-empty human-readable reason
    /// when the identifier is not allowed.
    /// </returns>
    string? GetRejectionReason(Identifier identifier);
}
