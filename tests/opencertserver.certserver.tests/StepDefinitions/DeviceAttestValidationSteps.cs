using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Server.Services;
using OpenCertServer.Tpm2Lib;
using Reqnroll;
using Xunit;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using AcmeAccount = Acme.Abstractions.Model.Account;
using AcmeChallenge = Acme.Abstractions.Model.Challenge;
using AcmeError = Acme.Abstractions.Model.AcmeError;
using AcmeIdentifier = Acme.Abstractions.Model.Identifier;
using AcmeOrder = Acme.Abstractions.Model.Order;
using AcmeAuthorization = Acme.Abstractions.Model.Authorization;
using DeviceAttestAnswer = Acme.Abstractions.Model.DeviceAttestChallengeAnswer;

/// <summary>
/// Step definitions for device-attest-validation.feature (GROUP 2 + code-review remediation).
/// Tests DeviceAttestChallengeValidator directly.
/// </summary>
[Binding]
public sealed class DeviceAttestValidationSteps : IDisposable
{
    private AcmeChallenge? _challenge;
    private AcmeAccount? _account;
    private bool _resultIsValid;
    private AcmeError? _resultError;
    private bool _secondResultIsValid;
    private AcmeError? _secondResultError;

    // Holds the CA cert to inject as a trusted root (S-II/S-I scenarios).
    private X509Certificate2? _testCa;

    // Shared validator instance — preserved across multiple When steps for anti-replay tests (S-III).
    private DeviceAttestChallengeValidator? _validator;

    private static readonly FieldInfo TokenBackingField =
        typeof(AcmeChallenge).GetField("<Token>k__BackingField",
            BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("Cannot find Token backing field on Challenge");

    // ─── Static helpers ───────────────────────────────────────────────────────

    private static AcmeAccount CreateTestAccount()
    {
        using var rsa = RSA.Create(2048);
        var securityKey = new RsaSecurityKey(rsa.ExportParameters(true));
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
        return new AcmeAccount(jwk, null, DateTimeOffset.UtcNow) { Status = AccountStatus.Valid };
    }

    private static AcmeChallenge CreateChallengeWithToken(string token)
    {
        var account = CreateTestAccount();
        var order = new AcmeOrder(account, [new AcmeIdentifier("dns", "test.example.com")], null)
        {
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        };
        var authorization = new AcmeAuthorization(order,
            new AcmeIdentifier("dns", "test.example.com"), DateTimeOffset.UtcNow.AddDays(1));
        var challenge = new AcmeChallenge(authorization, ChallengeTypes.DeviceAttest01);
        TokenBackingField.SetValue(challenge, token);
        return challenge;
    }

    private static string CertToBase64Url(X509Certificate2 cert) =>
        Convert.ToBase64String(cert.Export(X509ContentType.Cert))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static byte[] FromBase64Url(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        return (s.Length % 4) switch
        {
            2 => Convert.FromBase64String(s + "=="),
            3 => Convert.FromBase64String(s + "="),
            _ => Convert.FromBase64String(s)
        };
    }

    /// <summary>Creates a self-signed AIK cert (NOT issued by any CA).</summary>
    private static string CreateSelfSignedAikBase64Url()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=SelfSigned AIK", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
        return CertToBase64Url(cert);
    }

    /// <summary>
    /// Creates a test CA + an AIK cert signed by that CA.
    /// Caller owns the returned X509Certificate2 (caCert) and RSA (aikKey).
    /// </summary>
    private static (X509Certificate2 caCert, RSA aikKey, string aikCertBase64Url)
        CreateCaAndAikCert()
    {
        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=Test Manufacturer CA", caKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, false, 0, true));
        var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(10));

        var aikKey = RSA.Create(2048);
        var aikReq = new CertificateRequest("CN=Test AIK", aikKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var aikCert = aikReq.Create(caCert, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1), Guid.NewGuid().ToByteArray());

        return (caCert, aikKey, CertToBase64Url(aikCert));
    }

    /// <summary>
    /// Builds wire bytes for a Tpm2bAttest (size-prefixed TPMS_ATTEST) using the given
    /// nonce bytes. Pass <paramref name="magicOverride"/> or <paramref name="attestedOverride"/>
    /// to produce structurally invalid proof data for negative tests.
    /// </summary>
    private static byte[] BuildAttestBytes(
        byte[] nonceBytes,
        Generated magicOverride = Generated.Value,
        IAttestUnion? attestedOverride = null)
    {
        var quoteInfo = attestedOverride
            ?? new QuoteInfo(
                [new PcrSelection(TpmAlgId.Sha256, [0, 1, 2, 3, 4, 5, 6, 7])],
                new byte[32]);

        var attest = new Attest(magicOverride, [], nonceBytes,
            new ClockInfo(0u, 0u, 0u, 0), 0ul, quoteInfo);

        return Marshaller.GetTpmRepresentation(new Tpm2bAttest(attest));
    }

    /// <summary>Signs proofBytes with the AIK private key (RSA PKCS#1v15 SHA-256).</summary>
    private static string SignProof(byte[] proofBytes, RSA aikKey) =>
        ToBase64Url(aikKey.SignData(proofBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

    private static readonly JsonSerializerOptions TestSerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static string BuildExtraData(string nonce, string? aikCert, string proof, string? sig = null)
    {
        var answer = new DeviceAttestAnswer
        {
            Nonce = nonce,
            Proof = proof,
            Signature = sig,
            AikCertificate = aikCert
        };
        return JsonSerializer.Serialize(answer, TestSerializerOptions);
    }

    private DeviceAttestChallengeValidator GetOrCreateValidator(X509Certificate2? trustedCa)
    {
        if (_validator != null) return _validator;
        var roots = new X509Certificate2Collection();
        if (trustedCa != null) roots.Add(trustedCa);
        _validator = new DeviceAttestChallengeValidator(new StaticAttestationTrustProvider(roots));
        return _validator;
    }

    // ─── Given steps ─────────────────────────────────────────────────────────

    [Given("""
           a device-attest-01 challenge with token "(.*)"
           """)]
    public void GivenAChallengeWithToken(string token)
    {
        _account = CreateTestAccount();
        _challenge = CreateChallengeWithToken(token);
    }

    [Given("""the challenge has extra data with matching nonce "(.*)" and a self-signed AIK certificate""")]
    public void GivenSelfSignedAikNoTrustedRoot(string nonce)
    {
        Assert.NotNull(_challenge);
        _challenge.ExtraData = BuildExtraData(nonce, CreateSelfSignedAikBase64Url(),
            proof: ToBase64Url([1, 2, 3]));
    }

    [Given("""the challenge has extra data with matching nonce "(.*)", a trusted CA-signed AIK certificate, and a valid TPM proof signed by the AIK key""")]
    public void GivenValidCaSignedAikAndValidProof(string nonce)
    {
        Assert.NotNull(_challenge);
        var (caCert, aikKey, aikCertB64) = CreateCaAndAikCert();
        _testCa = caCert;

        var nonceBytes = FromBase64Url(nonce);
        var proofBytes = BuildAttestBytes(nonceBytes);
        _challenge.ExtraData = BuildExtraData(nonce, aikCertB64,
            proof: ToBase64Url(proofBytes),
            sig: SignProof(proofBytes, aikKey));
        aikKey.Dispose();
    }

    [Given("""the challenge has extra data with matching nonce "(.*)", a trusted CA-signed AIK certificate, and garbage proof bytes""")]
    public void GivenCaSignedAikGarbageProof(string nonce)
    {
        Assert.NotNull(_challenge);
        var (caCert, aikKey, aikCertB64) = CreateCaAndAikCert();
        _testCa = caCert;
        var garbage = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F }; // "Hello"
        _challenge.ExtraData = BuildExtraData(nonce, aikCertB64,
            proof: ToBase64Url(garbage),
            sig: SignProof(garbage, aikKey));
        aikKey.Dispose();
    }

    [Given("""the challenge has extra data with matching nonce "(.*)", a trusted CA-signed AIK certificate, and a proof with invalid TPM magic""")]
    public void GivenCaSignedAikWrongMagic(string nonce)
    {
        Assert.NotNull(_challenge);
        var (caCert, aikKey, aikCertB64) = CreateCaAndAikCert();
        _testCa = caCert;
        var nonceBytes = FromBase64Url(nonce);
        var proofBytes = BuildAttestBytes(nonceBytes, magicOverride: (Generated)0xDEADBEEF);
        _challenge.ExtraData = BuildExtraData(nonce, aikCertB64,
            proof: ToBase64Url(proofBytes),
            sig: SignProof(proofBytes, aikKey));
        aikKey.Dispose();
    }

    [Given("""the challenge has extra data with matching nonce "(.*)", a trusted CA-signed AIK certificate, and a proof with wrong attestation type""")]
    public void GivenCaSignedAikWrongType(string nonce)
    {
        Assert.NotNull(_challenge);
        var (caCert, aikKey, aikCertB64) = CreateCaAndAikCert();
        _testCa = caCert;
        var nonceBytes = FromBase64Url(nonce);
        // CertifyInfo produces TpmSt.AttestCertify, not TpmSt.AttestQuote
        var proofBytes = BuildAttestBytes(nonceBytes, attestedOverride: new CertifyInfo([], []));
        _challenge.ExtraData = BuildExtraData(nonce, aikCertB64,
            proof: ToBase64Url(proofBytes),
            sig: SignProof(proofBytes, aikKey));
        aikKey.Dispose();
    }

    [Given("""the challenge has extra data with matching nonce "(.*)", a trusted CA-signed AIK certificate, and a proof with mismatched extra data""")]
    public void GivenCaSignedAikMismatchedExtraData(string nonce)
    {
        Assert.NotNull(_challenge);
        var (caCert, aikKey, aikCertB64) = CreateCaAndAikCert();
        _testCa = caCert;
        var wrongNonce = new byte[32];
        Random.Shared.NextBytes(wrongNonce);
        var proofBytes = BuildAttestBytes(wrongNonce);
        _challenge.ExtraData = BuildExtraData(nonce, aikCertB64,
            proof: ToBase64Url(proofBytes),
            sig: SignProof(proofBytes, aikKey));
        aikKey.Dispose();
    }

    [Given("""the challenge has extra data with matching nonce "(.*)", a trusted CA-signed AIK certificate, and an empty proof""")]
    public void GivenCaSignedAikEmptyProof(string nonce)
    {
        Assert.NotNull(_challenge);
        var (caCert, _, aikCertB64) = CreateCaAndAikCert();
        _testCa = caCert;
        _challenge.ExtraData = BuildExtraData(nonce, aikCertB64, proof: string.Empty);
    }

    [Given("""
           the challenge has extra data with a different nonce "(.*)"
           """)]
    public void GivenTheChallengeHasExtraDataWithDifferentNonce(string differentNonce)
    {
        Assert.NotNull(_challenge);
        _challenge.ExtraData = BuildExtraData(differentNonce, CreateSelfSignedAikBase64Url(),
            proof: ToBase64Url([1, 2, 3]));
    }

    [Given(@"the challenge has no extra data")]
    public void GivenTheChallengeHasNoExtraData()
    {
        Assert.NotNull(_challenge);
        _challenge.ExtraData = null;
    }

    [Given("""the challenge has extra data with matching nonce "(.*)" but no AIK certificate""")]
    public void GivenTheChallengeHasExtraDataWithMatchingNonceButNoAik(string nonce)
    {
        Assert.NotNull(_challenge);
        _challenge.ExtraData = BuildExtraData(nonce, aikCert: null, proof: ToBase64Url([1, 2, 3]));
    }

    // ─── When steps ───────────────────────────────────────────────────────────

    [When(@"the server validates the challenge")]
    public async Task WhenTheServerValidatesTheChallenge()
    {
        Assert.NotNull(_challenge);
        var validator = GetOrCreateValidator(trustedCa: null);
        (_resultIsValid, _resultError) = await validator.ValidateChallenge(
            _challenge, _account ?? CreateTestAccount(), CancellationToken.None);
    }

    [When(@"the server validates the challenge with a trusted CA injected")]
    public async Task WhenTheServerValidatesTheChallengeWithTrustedCa()
    {
        Assert.NotNull(_challenge);
        var validator = GetOrCreateValidator(trustedCa: _testCa);
        (_resultIsValid, _resultError) = await validator.ValidateChallenge(
            _challenge, _account ?? CreateTestAccount(), CancellationToken.None);
    }

    [When(@"the server validates the same challenge again with a trusted CA injected")]
    public async Task WhenTheServerValidatesTheSameChallengeAgainWithTrustedCa()
    {
        Assert.NotNull(_challenge);
        // Reuse the same validator instance (anti-replay state is held per validator).
        var validator = GetOrCreateValidator(trustedCa: _testCa);
        (_secondResultIsValid, _secondResultError) = await validator.ValidateChallenge(
            _challenge, _account ?? CreateTestAccount(), CancellationToken.None);
    }

    // ─── Then steps ───────────────────────────────────────────────────────────

    [Then(@"the result is valid")]
    public void ThenTheResultIsValid() =>
        Assert.True(_resultIsValid, $"Expected valid but got error: {_resultError?.Type}: {_resultError?.Detail}");

    [Then(@"there is no error")]
    public void ThenThereIsNoError() => Assert.Null(_resultError);

    [Then(@"the result is not valid")]
    public void ThenTheResultIsNotValid() => Assert.False(_resultIsValid);

    [Then("""
          the error type contains "(.*)"
          """)]
    public void ThenTheErrorTypeContains(string expectedType)
    {
        Assert.NotNull(_resultError);
        Assert.Contains(expectedType, _resultError.Type, StringComparison.OrdinalIgnoreCase);
    }

    [Then(@"the second result is not valid")]
    public void ThenTheSecondResultIsNotValid() => Assert.False(_secondResultIsValid);

    [Then("""
          the second error type contains "(.*)"
          """)]
    public void ThenTheSecondErrorTypeContains(string expectedType)
    {
        Assert.NotNull(_secondResultError);
        Assert.Contains(expectedType, _secondResultError.Type, StringComparison.OrdinalIgnoreCase);
    }

    // ─── Disposal ─────────────────────────────────────────────────────────────

    public void Dispose()
    {
        _testCa?.Dispose();
        _validator = null;
    }
}
