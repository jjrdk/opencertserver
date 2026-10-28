using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NSubstitute;
using OpenCertServer.Ca.Utils.Validation;
using Reqnroll;
using Xunit;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

/// <summary>
/// Step definitions exercising the RFC 9525 <see cref="CertificateIdentityValidator"/>. The
/// reference-identity lookup is an injected <see cref="ILookUpServiceProvider"/> supplied by an
/// NSubstitute mock (no concrete implementation is required); certificates are built on the fly with
/// the <see cref="SubjectAlternativeNameBuilder"/> so the parser reads real extension bytes.
///
/// All per-scenario state is (re)initialised in the background "a service provider lookup" step, so
/// every scenario starts from a clean slate regardless of the Reqnroll binding lifetime.
/// </summary>
[Binding]
public sealed partial class CertificateIdentityValidationSteps
{
    // ---- Per-scenario state --------------------------------------------------------------
    private ILookUpServiceProvider _lookup = null!;
    private List<ServiceIdentity> _resolved = new();

    private ServiceIdentity? _reference;

    private bool _certificatePresent = true;
    private X500DistinguishedName _dn = new("CN=localhost");
    private readonly List<string> _dnsSans = new();
    private readonly List<IPAddress> _ipSans = new();
    private readonly List<Uri> _uriSans = new();

    private CertificateIdentityValidationResult? _result;
    private Exception? _exception;
    private bool? _directMatch;

    // ---- Background ----------------------------------------------------------------------

    [Given("a service provider lookup")]
    public void GivenAServiceProviderLookup()
    {
        _lookup = Substitute.For<ILookUpServiceProvider>();
        _resolved = new();
        _reference = null;
        _certificatePresent = true;
        _dn = new X500DistinguishedName("CN=localhost");
        _dnsSans.Clear();
        _ipSans.Clear();
        _uriSans.Clear();
        _result = null;
        _exception = null;
        _directMatch = null;

        // Default behaviour: the lookup returns the reference-identity set configured by the
        // "lookup resolves to ..." steps. Because List<T> is a reference type, Task.FromResult
        // captures the same instance that those steps mutate in place, so a later-populated list
        // is what the lookup finally yields (and an empty one when nothing was configured).
        _lookup
            .ResolveServiceIdentities(Arg.Any<ServiceIdentity>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<IReadOnlyList<ServiceIdentity>>(_resolved));
    }

    // ---- Given: reference & service ------------------------------------------------------

    [Given("the reference service is DNS name {string}")]
    public void TheReferenceServiceIsDnsName(string name)
    {
        _reference = ServiceIdentity.Dns(name);
    }

    [Given("the reference service is IP address {string}")]
    public void TheReferenceServiceIsIpAddress(string address)
    {
        _reference = ServiceIdentity.Ip(address);
    }

    [Given("the reference service is URI {string}")]
    public void TheReferenceServiceIsUri(string uri)
    {
        _reference = ServiceIdentity.Uri(uri);
    }

    [Given("the lookup resolves to DNS name {string}")]
    public void TheLookupResolvesToDnsName(string name)
    {
        _resolved.Add(ServiceIdentity.Dns(name));
    }

    [Given("the lookup resolves to IP address {string}")]
    public void TheLookupResolvesToIpAddress(string address)
    {
        _resolved.Add(ServiceIdentity.Ip(address));
    }

    [Given("the lookup resolves to URI {string}")]
    public void TheLookupResolvesToUri(string uri)
    {
        _resolved.Add(ServiceIdentity.Uri(uri));
    }

    // ---- Given: certificate under test ---------------------------------------------------

    [Given("the certificate presents DNS name {string}")]
    public void TheCertificatePresentsDnsName(string name)
    {
        _dnsSans.Add(name);
    }

    [Given("the certificate presents IP address {string}")]
    public void TheCertificatePresentsIpAddress(string address)
    {
        _ipSans.Add(IPAddress.Parse(address));
    }

    [Given("the certificate presents URI {string}")]
    public void TheCertificatePresentsUri(string uri)
    {
        _uriSans.Add(new Uri(uri, UriKind.Absolute));
    }

    [Given("the certificate has subject {string}")]
    public void TheCertificateHasSubject(string distinguishedName)
    {
        _dn = new X500DistinguishedName(distinguishedName);
    }

    [Given("the certificate presents no subject alternative names")]
    public void TheCertificatePresentsNoSubjectAlternativeNames()
    {
        // No SAN step is required: a certificate built with zero SANs carries no subjectAltName,
        // which is exactly the "no acceptable identifier" condition. The step exists to document
        // the intent in the scenario.
    }

    [Given("the certificate is absent")]
    public void TheCertificateIsAbsent()
    {
        _certificatePresent = false;
    }

    // ---- Given: matcher exercised directly (non-certificate paths) -----------------------

    [Given("the matcher compares SRV name {string} against the presented SRV name {string}")]
    public void TheMatcherComparesSrv(string referenceName, string presentedName)
    {
        // SRVName has no SAN encoding that this simple parser exposes, so SRV matching is exercised
        // directly on the IdentityMatcher core, per RFC 9525 section 6.2.
        _directMatch = IdentityMatcher.Matches(ServiceIdentity.Srv(referenceName), ServiceIdentity.Srv(presentedName));
    }

    // ---- When --------------------------------------------------------------------------

    [When("the certificate is validated for the reference service")]
    public async Task TheCertificateIsValidatedForTheReferenceService()
    {
        await Validate(_reference);
    }

    [When("the certificate is validated for the absent reference service")]
    public async Task TheCertificateIsValidatedForTheAbsentReferenceService()
    {
        await Validate(null);
    }

    private async Task Validate(ServiceIdentity? reference)
    {
        var validator = new CertificateIdentityValidator(_lookup);
        try
        {
            // The validator throws ArgumentNullException for a null reference or certificate; those
            // paths are exercised deliberately below, hence the null-forgiving operators.
            _result = await validator.Validate(reference!, BuildCertificate()!);
        }
        catch (Exception exception)
        {
            _exception = exception;
        }
    }

    // ---- Then: result -------------------------------------------------------------------

    [Then("the result is a match for the reference service")]
    public void TheResultIsAMatchForTheReferenceService()
    {
        Assert.NotNull(_result);
        Assert.True(_result!.IsMatch, $"Expected a match, but the validation failed with: {_result!.Failure}");
        Assert.Equal(_reference, _result.MatchedIdentifier);
    }

    [Then("the result is a match")]
    public void TheResultIsAMatch()
    {
        Assert.NotNull(_result);
        Assert.True(_result!.IsMatch, $"Expected a match, but the validation failed with: {_result!.Failure}");
    }

    [Then("the result does not match")]
    public void TheResultDoesNotMatch()
    {
        Assert.NotNull(_result);
        Assert.False(_result!.IsMatch, $"Expected no match, but the validation matched: {_result!.MatchedIdentifier}");
    }

    [Then("the result fails with {string}")]
    public void TheResultFailsWithTheReason(string reason)
    {
        Assert.NotNull(_result);
        Assert.False(_result!.IsMatch, "Expected the validation to fail.");
        Assert.Equal(ExpectedFailure(reason), _result.Failure);
    }

    [Then("the service provider lookup was consulted for the reference service")]
    public void TheServiceProviderLookupWasConsultedForTheReferenceService()
    {
        // Proves the validator actually resolves reference identities through the injected lookup,
        // not from some hard-coded source.
        _lookup.Received(1)
            .ResolveServiceIdentities(Arg.Any<ServiceIdentity>(), Arg.Any<CancellationToken>());
    }

    [Then("the match is found")]
    public void TheMatchIsFound()
    {
        Assert.True(_directMatch, "Expected the identifiers to match.");
    }

    [Then("the match is not found")]
    public void TheMatchIsNotFound()
    {
        Assert.True(_directMatch is false, "Expected the identifiers NOT to match.");
    }

    [Then("an argument exception is thrown")]
    public void AnArgumentExceptionIsThrown()
    {
        // ArgumentNullException IS-A ArgumentException; a runtime 'is' check accepts both and avoids
        // xUnit's exact-type Assert.Throws<T> pitfall.
        Assert.True(_exception is ArgumentException,
            $"Expected an ArgumentException, but got: {_exception?.GetType().Name ?? "no exception"}");
    }

    // ---- Helpers -------------------------------------------------------------------------

    private static CertificateIdentityValidationFailure? ExpectedFailure(string reason) => reason switch
    {
        "missing subject alternative name" => CertificateIdentityValidationFailure.MissingSubjectAlternativeName,
        "no reference identities" => CertificateIdentityValidationFailure.NoReferenceIdentities,
        "no match" => CertificateIdentityValidationFailure.NoMatch,
        _ => throw new ArgumentException($"Unknown failure reason: '{reason}'."),
    };

    private X509Certificate2? BuildCertificate()
    {
        if (!_certificatePresent)
        {
            return null;
        }

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(_dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        if (_dnsSans.Count + _ipSans.Count + _uriSans.Count > 0)
        {
            var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
            foreach (var dns in _dnsSans)
            {
                subjectAlternativeNames.AddDnsName(dns);
            }
            foreach (var ip in _ipSans)
            {
                subjectAlternativeNames.AddIpAddress(ip);
            }
            foreach (var uri in _uriSans)
            {
                subjectAlternativeNames.AddUri(uri);
            }
            request.CertificateExtensions.Add(subjectAlternativeNames.Build(false));
        }

        // Valid for a year so the SAN-bearing extension is what we exercise; validity dates and PKIX
        // path validation are explicitly out of scope for RFC 9525 identity matching.
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
