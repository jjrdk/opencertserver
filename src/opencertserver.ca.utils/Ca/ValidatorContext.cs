namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// The context passed to a single <see cref="IValidateCertificateRequests"/>. It carries the request being validated plus the
/// requestor / reenrollment identity, the request-id (from T03, when present), and the annotations accumulated by
/// earlier validators. Validators are read-only on this object except for appending to <see cref="Annotations"/>.
///
/// For the <see cref="ValidatorPhase.Post"/> phase the pipeline sets <see cref="IssuedCertificate"/> to the
/// certificate that was just signed so post-issue validators can inspect it.
/// </summary>
public sealed class ValidatorContext
{
	/// <summary>The certificate request being validated.</summary>
	public required CertificateRequest Request { get; init; }

	/// <summary>The issuing profile (may be <c>null</c> for the default profile).</summary>
	public string? Profile { get; init; }

	/// <summary>The authenticated requestor identity, or <c>null</c> when unauthenticated.</summary>
	public ClaimsIdentity? Requestor { get; init; }

	/// <summary>The certificate being reenrolled from, for <c>reEnrollment</c> requests (RFC 7030 §4.4).</summary>
	public X509Certificate2? ReenrollingFrom { get; init; }

	/// <summary>The request-id (from T03) when present, otherwise <c>null</c>.</summary>
	public string? RequestId { get; init; }

	/// <summary>The cancellation token for the operation.</summary>
	public CancellationToken CancellationToken { get; init; }

	/// <summary>
	/// Annotations accumulated by earlier validators (e.g. <see cref="ValidationResult.NeedsApprovalAnnotation"/>).
	/// Earlier validators may append; later validators read the current contents.
	/// </summary>
	public List<string> Annotations { get; } = new();

	/// <summary>
	/// The certificate that was just signed; set by the pipeline when running the <see cref="ValidatorPhase.Post"/>
	/// phase and <c>null</c> for the pre-sign phases.
	/// </summary>
	public X509Certificate2? IssuedCertificate { get; set; }

	/// <summary>Create a context for a new enrollment / re-enrollment.</summary>
	public static ValidatorContext Create(
		CertificateRequest request,
		string? profile,
		ClaimsIdentity? requestor,
		X509Certificate2? reenrollingFrom = null,
		string? requestId = null,
		CancellationToken cancellationToken = default) =>
		new()
		{
			Request = request,
			Profile = profile,
			Requestor = requestor,
			ReenrollingFrom = reenrollingFrom,
			RequestId = requestId,
			CancellationToken = cancellationToken,
		};
}
