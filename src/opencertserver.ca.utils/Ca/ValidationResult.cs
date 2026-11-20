namespace OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// The outcome of a single <see cref="IValidateCertificateRequests"/>.
/// </summary>
public enum ValidationOutcome
{
    /// <summary>The request passed this validator.</summary>
    Passed = 0,

    /// <summary>The request is rejected and should not be issued.</summary>
    Rejected = 1,

    /// <summary>The request is not invalid but cannot be issued unconditionally — it needs human approval (T04).</summary>
    NeedsApproval = 2,
}

/// <summary>
/// The result of running a single <see cref="IValidateCertificateRequests"/>. A validator returns a <see cref="ValidationResult"/>;
/// a <see cref="ValidationOutcome.Passed"/> (the default) means "no objection".
///
/// A <see cref="ValidationOutcome.Rejected"/> result carries a <see cref="Reason"/>. By default a rejection
/// <b>short-circuits</b> the pipeline (later phases stop running); set <see cref="ShortCircuit"/> to <c>false</c>
/// to record the rejection and continue (aggregate mode, matching the historical "run all validators and join the
/// error messages" behaviour of the pre-pipeline code).
///
/// A <see cref="ValidationOutcome.NeedsApproval"/> result records an annotation (default <c>"needs-approval"</c>) and
/// does not short-circuit — the approval gate is wired by T04.
/// </summary>
public readonly record struct ValidationResult(
    ValidationOutcome Outcome,
    string? Reason,
    string? Annotation,
    bool ShortCircuit)
{
    /// <summary>A passing result (no objection).</summary>
    public static readonly ValidationResult Passed = new(ValidationOutcome.Passed, null, null, false);

    /// <summary>The well-known annotation used when a validator requests human approval.</summary>
    public const string NeedsApprovalAnnotation = "needs-approval";

    /// <summary>Create a rejection. By default a rejection short-circuits the pipeline.</summary>
    /// <param name="reason">Human-readable reason.</param>
    /// <param name="shortCircuit">
    /// When <c>true</c> (the default), later phases stop running. When <c>false</c>, the rejection is recorded and
    /// the pipeline continues (aggregate mode).
    /// </param>
    public static ValidationResult Reject(string reason, bool shortCircuit = true) =>
        new(ValidationOutcome.Rejected, reason, null, shortCircuit);

    /// <summary>Create a rejection that is <b>recorded but does not short-circuit</b> (aggregate mode).</summary>
    public static ValidationResult Error(string reason) =>
        new(ValidationOutcome.Rejected, reason, null, ShortCircuit: false);

    /// <summary>Create a "needs approval" result (records an annotation, does not short-circuit).</summary>
    /// <param name="reason">Human-readable reason the request needs approval.</param>
    /// <param name="annotation">The annotation to record (defaults to <see cref="NeedsApprovalAnnotation"/>).</param>
    public static ValidationResult NeedsApproval(string reason, string? annotation = null) =>
        new(ValidationOutcome.NeedsApproval, reason, annotation, ShortCircuit: false);

    /// <summary>True when the validator objected to the request.</summary>
    public bool IsError => Outcome is ValidationOutcome.Rejected;

    /// <summary>True when the validator passed.</summary>
    public bool IsPassed => Outcome == ValidationOutcome.Passed;

    /// <summary>True when the validator requested human approval.</summary>
    public bool RequiresApproval => Outcome == ValidationOutcome.NeedsApproval;
}
