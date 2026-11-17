namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

public interface IValidateCertificateRequests
{
    /// <summary>
    /// Validates a request in the phased pipeline. Existing request validators are adapted by default: a
    /// <c>null</c> error passes, while a non-null error is recorded and the pipeline continues.
    /// </summary>
    /// <param name="context">The complete validation context.</param>
    /// <param name="cancellationToken">The cancellation token for asynchronous operations.</param>
    /// <returns>The outcome for this validator.</returns>
    Task<ValidationResult> Validate(IssuingContext context, CancellationToken cancellationToken = default);
}

/// <summary>
/// Defines the interface for validating certificate requests.
/// </summary>
public interface IValidateCertificateRequests<TIssuingContext> : IValidateCertificateRequests
    where TIssuingContext : IssuingContext
{
    async Task<ValidationResult> IValidateCertificateRequests.Validate(IssuingContext context, CancellationToken cancellationToken)
    {
        if (context is not TIssuingContext typedContext)
        {
            throw new ArgumentException($"{GetType().Name} expected context of type {typeof(TIssuingContext).Name}, but got {context.GetType().Name}.", nameof(context));
        }

        return await Validate(typedContext, cancellationToken);
    }

    /// <summary>
    /// Validates a request in the phased pipeline. Existing request validators are adapted by default: a
    /// <c>null</c> error passes, while a non-null error is recorded and the pipeline continues.
    /// </summary>
    /// <param name="context">The complete validation context.</param>
    /// <param name="cancellationToken">The cancellation token for asynchronous operations.</param>
    /// <returns>The outcome for this validator.</returns>
    Task<ValidationResult> Validate(TIssuingContext context, CancellationToken cancellationToken = default);
}

/// <summary>
/// Converts a CSR into the values that should be checked against the authenticated identity.
/// Implementations may read the CSR, the caller identity, and optional profile metadata to decide
/// which values are allowed for the request. Returning null/empty results means the converter does
/// not impose an identity restriction for this request.
/// </summary>
public interface ICertificateRequestValueConverter
{
    /// <summary>
    /// Gets the candidate values embedded in the CSR that should be compared to the authenticated identity.
    /// </summary>
    IReadOnlyCollection<string> GetValues(
        CertificateRequest request,
        string? profile = null,
        ClaimsIdentity? requestor = null);
}
