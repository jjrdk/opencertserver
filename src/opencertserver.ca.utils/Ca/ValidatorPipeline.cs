namespace OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// A validator together with the phase and order the <see cref="ValidatorPipeline"/> should run it in, plus the
/// operator/config <c>name</c> used to bind per-validator settings (e.g. <c>Validators__&lt;Name&gt;__Enabled</c>).
/// </summary>
public sealed record ValidatorRegistration(string Name, ValidatorPhase Phase, int Order, IValidateCertificateRequests Validator);

/// <summary>
/// The result of running an <see cref="IValidatorPipeline"/>.
/// </summary>
/// <param name="Status">
/// <see cref="ValidationOutcome.Passed"/> when every validator passed, <see cref="ValidationOutcome.Rejected"/> when
/// a validator objected (see <see cref="Reasons"/>), or <see cref="ValidationOutcome.NeedsApproval"/> when a validator
/// requested approval and nothing rejected.
/// </param>
/// <param name="Reasons">The rejection reasons (empty when not rejected), joined by the caller.</param>
/// <param name="Annotations">Annotations recorded by validators (e.g. <see cref="ValidationResult.NeedsApprovalAnnotation"/>).</param>
public sealed record ValidatorPipelineResult(ValidationOutcome Status, IReadOnlyList<string> Reasons, IReadOnlyList<string> Annotations)
{
	/// <summary>A passing pipeline result.</summary>
	public static readonly ValidatorPipelineResult Passed =
		new(ValidationOutcome.Passed, Array.Empty<string>(), Array.Empty<string>());

	/// <summary>True when the pipeline rejected the request.</summary>
	public bool IsRejected => Status == ValidationOutcome.Rejected;

	/// <summary>True when the pipeline passed (no rejection, no approval request).</summary>
	public bool IsApproved => Status == ValidationOutcome.Passed;

	/// <summary>True when the pipeline requested human approval (and nothing rejected).</summary>
	public bool RequiresApproval => Status == ValidationOutcome.NeedsApproval;

	internal static ValidatorPipelineResult From(IReadOnlyList<string> reasons, IReadOnlyList<string> annotations)
	{
		var status = reasons.Count > 0
			? ValidationOutcome.Rejected
			: annotations.Contains(ValidationResult.NeedsApprovalAnnotation)
				? ValidationOutcome.NeedsApproval
				: ValidationOutcome.Passed;
		return new(status, reasons, annotations);
	}
}

/// <summary>
/// The ordered, phased validator pipeline. Pre-sign phases (<see cref="ValidatorPhase.Approval"/> through
/// <see cref="ValidatorPhase.PreSign"/>) run before a request is signed; <see cref="ValidatorPhase.Post"/> runs after
/// signing (the issued certificate is supplied to the validators).
///
/// <para>
/// A <see cref="ValidationResult.ShortCircuit"/> rejection stops the pipeline immediately; a non-short-circuiting
/// rejection (aggregate mode, e.g. the historical request validators) is recorded and the pipeline continues, so all
/// validators run and their errors are joined — preserving the pre-pipeline behaviour.
/// </para>
///
/// Hook points: <c>BeforeIssue</c> = <see cref="Run"/> (the pre-sign phases), the <see cref="ValidatorPhase.PreSign"/>
/// phase is the last pre-sign gate, and <c>PostIssue</c> = <see cref="RunPost"/> (the <see cref="ValidatorPhase.Post"/>
/// phase).
/// </summary>
public interface IValidatorPipeline
{
	/// <summary>Run the pre-sign phases (Approval, Data, Issuance, PreSign) — the <c>BeforeIssue</c> / <c>PreSign</c> gate.</summary>
	Task<ValidatorPipelineResult> Run(ValidatorContext context, CancellationToken cancellationToken = default);

	/// <summary>Run the post-issue phase (Post) — the <c>PostIssue</c> hook. Call after the certificate is signed and
	/// with <see cref="ValidatorContext.IssuedCertificate"/> set.</summary>
	Task<ValidatorPipelineResult> RunPost(ValidatorContext context, CancellationToken cancellationToken = default);
}

/// <summary>
/// The default <see cref="IValidatorPipeline"/> implementation. Validators are grouped by phase and run in the
/// configured phase order (default: Approval, Data, Issuance, PreSign, Post); within a phase, by ascending
/// registration order.
/// </summary>
public sealed class ValidatorPipeline : IValidatorPipeline
{
	// The canonical, fixed phase order. Kept as a constant so it is AOT-safe (no Enum.GetValues reflection).
	public static readonly IReadOnlyList<ValidatorPhase> DefaultPhaseOrder =
		[ValidatorPhase.Approval, ValidatorPhase.Data, ValidatorPhase.Issuance, ValidatorPhase.PreSign, ValidatorPhase.Post];

	private readonly Dictionary<ValidatorPhase, List<ValidatorRegistration>> _byPhase;
	private readonly IReadOnlyList<ValidatorPhase> _phaseOrder;

	private ValidatorPipeline(IReadOnlyList<ValidatorPhase> phaseOrder, params ValidatorRegistration[] registrations)
	{
		_phaseOrder = phaseOrder.Count > 0 ? phaseOrder : DefaultPhaseOrder;
		_byPhase = new();
		foreach (var registration in registrations)
		{
			if (!_byPhase.TryGetValue(registration.Phase, out var validators))
			{
				validators = new List<ValidatorRegistration>();
				_byPhase[registration.Phase] = validators;
			}
			validators.Add(registration);
		}

		foreach (var validators in _byPhase.Values)
		{
			validators.Sort((a, b) => a.Order.CompareTo(b.Order));
		}
	}

	/// <summary>Build a pipeline from registrations, using the default (fixed) phase order.</summary>
	public static ValidatorPipeline Create(params ValidatorRegistration[] registrations) =>
		new(DefaultPhaseOrder, registrations);

	/// <summary>Build a pipeline from registrations, using an explicit phase order (config <c>Validators__Phases</c>).</summary>
	public static ValidatorPipeline Create(IReadOnlyList<ValidatorPhase> phaseOrder, params ValidatorRegistration[] registrations) =>
		new(phaseOrder, registrations);

	/// <summary>
	/// Build registrations for the historical request validators. They run in the
	/// <see cref="ValidatorPhase.Issuance"/> phase in registration order. Their default pipeline overload maps
	/// failures to aggregate results, preserving the historical behavior where every validator runs and errors join.
	/// </summary>
	public static IEnumerable<ValidatorRegistration> FromCertificateRequestRegistrations(params IValidateCertificateRequests[] validators)
	{
		var registrations = new List<ValidatorRegistration>(validators.Length);
		for (var i = 0; i < validators.Length; i++)
		{
			var validator = validators[i];
			var name = validator.GetType().Name;
			registrations.Add(new ValidatorRegistration(
				name,
				ValidatorPhase.Issuance,
				i,
				validator));
		}

		return registrations;
	}

	/// <summary>Build a default pipeline from a set of legacy <see cref="IValidateCertificateRequests"/> validators.</summary>
	public static ValidatorPipeline FromCertificateRequestValidators(params IValidateCertificateRequests[] validators) =>
		Create(FromCertificateRequestRegistrations(validators).ToArray());

	/// <summary>Run a single set of phases, recording rejections and annotations.</summary>
	private async Task<ValidatorPipelineResult> RunPhasesAsync(
		ValidatorContext context,
		IEnumerable<ValidatorPhase> phases,
		CancellationToken cancellationToken)
	{
		var reasons = new List<string>();
		foreach (var phase in phases)
		{
			if (!_byPhase.TryGetValue(phase, out var validators))
			{
				continue;
			}

			foreach (var registration in validators)
			{
				var validator = registration.Validator;
				var result = await validator.Validate(context, cancellationToken);
				if (result.IsError)
				{
					reasons.Add(result.Reason ?? $"Validator {registration.Name} rejected the request.");
					if (result.ShortCircuit)
					{
						// Short-circuit: stop the pipeline.
						return ValidatorPipelineResult.From(reasons, context.Annotations);
					}
					continue; // aggregate mode: record and continue
				}

				if (result.RequiresApproval && result.Annotation is not null)
				{
					context.Annotations.Add(result.Annotation);
				}
			}
		}

		return ValidatorPipelineResult.From(reasons, context.Annotations);
	}

	/// <inheritdoc/>
	public Task<ValidatorPipelineResult> Run(ValidatorContext context, CancellationToken cancellationToken = default)
	{
		var preSignPhases = _phaseOrder.TakeWhile(phase => phase != ValidatorPhase.Post);
		return RunPhasesAsync(context, preSignPhases, cancellationToken);
	}

	/// <inheritdoc/>
	public Task<ValidatorPipelineResult> RunPost(ValidatorContext context, CancellationToken cancellationToken = default) =>
		RunPhasesAsync(context, [ValidatorPhase.Post], cancellationToken);
}
