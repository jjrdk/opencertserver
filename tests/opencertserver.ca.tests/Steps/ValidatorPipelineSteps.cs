namespace OpenCertServer.Ca.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Ca;
using Reqnroll;
using Xunit;

/// <summary>
/// Step definitions for the phased <see cref="IValidatorPipeline"/> feature (T09). Each scenario builds a pipeline
/// from a small set of recording validators and asserts on the phase order, short-circuiting, aggregation, and
/// annotation behaviour.
/// </summary>
[Binding]
public sealed partial class ValidatorPipelineSteps
{
	private readonly List<ValidatorPhase> _executedPhases;
	private readonly List<RecordingValidator> _validators;
	private PreIssuingContext _preContext;
	private PostIssuingContext _postContext;
	private ValidatorPipelineResult _result;

	public ValidatorPipelineSteps(ScenarioContext scenarioContext)
	{
		_executedPhases = new List<ValidatorPhase>();
		_validators = new List<RecordingValidator>();
		_preContext = null!;
		_postContext = null!;
		_result = ValidatorPipelineResult.Passed;
	}

	[Given(@"a certificate request that is otherwise valid")]
	public void Given_A_Certificate_Request_That_Is_Otherwise_Valid()
	{
		_validators.Clear();
		_executedPhases.Clear();
		_result = ValidatorPipelineResult.Passed;
		_preContext = null!;
	}

	[Given("""^a validator in the "([^"]+)" phase that passes$""")]
	public void Given_A_Validator_In_The_Phase_That_Passes(string phase)
	{
		AddValidator(ParsePhase(phase), ValidatorBehaviour.Pass);
	}

	[Given("""^a validator in the "([^"]+)" phase that rejects and short-circuits$""")]
	public void Given_A_Validator_In_The_Phase_That_Rejects_And_Short_Circuits(string phase)
	{
		AddValidator(ParsePhase(phase), ValidatorBehaviour.Reject, shortCircuit: true);
	}

	[Given("""^a validator in the "([^"]+)" phase that rejects$""")]
	public void Given_A_Validator_In_The_Phase_That_Rejects(string phase)
	{
		// A bare "rejects" is a short-circuiting rejection (the EJBCA default).
		AddValidator(ParsePhase(phase), ValidatorBehaviour.Reject, shortCircuit: true);
	}

	[Given("""^a validator in the "([^"]+)" phase that rejects without short-circuiting$""")]
	public void Given_A_Validator_In_The_Phase_That_Rejects_Without_Short_Circuiting(string phase)
	{
		AddValidator(ParsePhase(phase), ValidatorBehaviour.Reject, shortCircuit: false);
	}

	[Given("""^a validator in the "([^"]+)" phase that annotates the request with "([^"]+)"$""")]
	public void Given_A_Validator_In_The_Phase_That_Annotates_The_Request_With(string phase, string annotation)
	{
		AddValidator(ParsePhase(phase), ValidatorBehaviour.NeedsApproval, annotation: annotation);
	}

	[When(@"the pipeline runs the request")]
	public Task When_The_Pipeline_Runs_The_Request()
	{
		_preContext = PreIssuingContext.Create(SampleRequest, null, null);
		_result = BuildPipeline().RunPre(_preContext).GetAwaiter().GetResult();
		return Task.CompletedTask;
	}

	[When(@"the pipeline runs the post-issue phase with the signed certificate")]
	public Task When_The_Pipeline_Runs_The_Post_Issue_Phase_With_The_Signed_Certificate()
	{
		_postContext = PostIssuingContext.Create(SampleIssuedCertificate, null, null);
		_result = BuildPipeline().RunPost(_postContext).GetAwaiter().GetResult();
		return Task.CompletedTask;
	}

	[Then("""^the validators ran in the order "([^"]+)"$""")]
	public void Then_The_Validators_Ran_In_The_Order(string expected)
	{
		var expectedPhases = expected
			.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
			.Select(ParsePhase)
			.ToList();
		Assert.Equal(expectedPhases, _executedPhases);
	}

	[Then(@"the pipeline rejected the request")]
	public void Then_The_Pipeline_Rejected_The_Request()
	{
		Assert.True(_result.IsRejected, $"Expected the pipeline to reject the request, but the outcome was {_result.Status}.");
	}

	[Then(@"the pipeline approved the request")]
	public void Then_The_Pipeline_Approved_The_Request()
	{
		Assert.True(_result.IsApproved, $"Expected the pipeline to approve the request, but the outcome was {_result.Status}.");
	}

	[Then(@"the pipeline requires approval")]
	public void Then_The_Pipeline_Requires_Approval()
	{
		Assert.True(_result.RequiresApproval, $"Expected the pipeline to require approval, but the outcome was {_result.Status}.");
	}

	[Then("""^the request is annotated with "([^"]+)"$""")]
	public void Then_The_Request_Is_Annotated_With(string annotation)
	{
		Assert.Contains(annotation, _result.Annotations);
	}

	[Then(@"the request is not annotated")]
	public void Then_The_Request_Is_Not_Annotated()
	{
		Assert.Empty(_result.Annotations);
	}

	[Then("""^the validator in the "([^"]+)" phase did not run$""")]
	public void Then_The_Validator_In_The_Phase_Did_Not_Run(string phase)
	{
		Assert.DoesNotContain(ParsePhase(phase), _executedPhases);
	}

	[Then("""^the validator in the "([^"]+)" phase did run$""")]
	public void Then_The_Validator_In_The_Phase_Did_Run(string phase)
	{
		Assert.Contains(ParsePhase(phase), _executedPhases);
	}

	[Then("""^the validator in the "([^"]+)" phase ran with the issued certificate$""")]
	public void Then_The_Validator_In_The_Phase_Ran_With_The_Issued_Certificate(string phase)
	{
		Assert.Contains(ParsePhase(phase), _executedPhases);
		Assert.NotNull(_postContext.IssuedCertificate);
	}

	private static CertificateRequest SampleRequest { get; } =
		new(new X500DistinguishedName("CN=validator-pipeline-test"), ECDsa.Create(), HashAlgorithmName.SHA256);

	private static X509Certificate2 SampleIssuedCertificate { get; } =
		SampleRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

	private ValidatorPipeline BuildPipeline()
	{
		var registrations = new List<ValidatorRegistration>(_validators.Count);
		for (var i = 0; i < _validators.Count; i++)
		{
			var validator = _validators[i];
			registrations.Add(new ValidatorRegistration(validator.Phase.ToString(), validator.Phase, i, validator));
		}

		return ValidatorPipeline.Create(registrations.ToArray());
	}

	private void AddValidator(ValidatorPhase phase, ValidatorBehaviour behaviour, bool shortCircuit = true, string? annotation = null)
	{
		_validators.Add(new RecordingValidator(phase, behaviour, shortCircuit, annotation, _executedPhases.Add));
	}

	private static ValidatorPhase ParsePhase(string phase) =>
		Enum.Parse<ValidatorPhase>(phase, ignoreCase: true);

	private enum ValidatorBehaviour
	{
		Pass,
		Reject,
		NeedsApproval,
	}

	/// <summary>A validator that records which phase it ran in and returns a configurable result.</summary>
	private sealed class RecordingValidator : IValidateCertificateRequests
	{
		private readonly ValidatorPhase _phase;
		private readonly ValidatorBehaviour _behaviour;
		private readonly bool _shortCircuit;
		private readonly string? _annotation;
		private readonly Action<ValidatorPhase> _onRun;

		public RecordingValidator(
			ValidatorPhase phase,
			ValidatorBehaviour behaviour,
			bool shortCircuit,
			string? annotation,
			Action<ValidatorPhase> onRun)
		{
			_phase = phase;
			_behaviour = behaviour;
			_shortCircuit = shortCircuit;
			_annotation = annotation;
			_onRun = onRun;
		}

		public ValidatorPhase Phase => _phase;

		public Task<ValidationResult> Validate(IssuingContext context, CancellationToken cancellationToken = default)
		{
			_onRun(_phase);
			return _behaviour switch
			{
				ValidatorBehaviour.Reject => Task.FromResult(ValidationResult.Reject($"Rejected by the {_phase} phase.", _shortCircuit)),
				ValidatorBehaviour.NeedsApproval => Task.FromResult(ValidationResult.NeedsApproval("Needs approval", _annotation)),
				_ => Task.FromResult(ValidationResult.Passed),
			};
		}
	}
}
