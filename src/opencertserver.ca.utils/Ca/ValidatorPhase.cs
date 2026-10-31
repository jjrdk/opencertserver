namespace OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// The phase a <see cref="IValidateCertificateRequests"/> participates in. Phases run in the fixed order
/// <see cref="Approval"/>, <see cref="Data"/>, <see cref="Issuance"/>, <see cref="PreSign"/>, <see cref="Post"/>.
/// This mirrors the EJBCA validator model (Approval / Data / Issuance / PreSign / Post) and lets operators
/// reason about *where* a check happens. The pre-sign phases (Approval..PreSign) run before the request is
/// signed; <see cref="Post"/> runs after signing (the issued certificate is passed to the validators).
/// </summary>
public enum ValidatorPhase
{
	/// <summary>Identity / authorization / "who is the requestor" — the earliest gate.</summary>
	Approval = 0,

	/// <summary>Request data / policy — profile, distinguished-name, extension rules.</summary>
	Data = 1,

	/// <summary>Issuance decision — may-issue / revocation / key material checks.</summary>
	Issuance = 2,

	/// <summary>Pre-sign — last pre-sign gate (e.g. final sanity before the signature is applied).</summary>
	PreSign = 3,

	/// <summary>Post-issue — runs after signing, on the issued certificate (hook point: PostIssue).</summary>
	Post = 4,
}
