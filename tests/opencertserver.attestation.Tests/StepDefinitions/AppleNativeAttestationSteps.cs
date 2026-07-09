using System.Security.Cryptography;
using System.Text;
using OpenCertServer.Attestation.Native;
using Reqnroll;
using Xunit;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

/// <summary>
/// Step definitions for the <c>AppleNativeAttestation.feature</c> feature.
/// On macOS: exercises the real <see cref="SecurityFrameworkAppleAttestInterop"/> — no mocks.
/// On non-macOS: the "available on this platform" step marks non-applicable scenarios as
/// skipped so CI passes on Linux/Windows.
/// </summary>
[Binding]
[Scope(Feature = "Apple Native Attestation (macOS)")]
public sealed class AppleNativeAttestationSteps : IDisposable
{
    private SecurityFrameworkAppleAttestInterop? _interop;
    private bool _platformAvailable;
    private Exception? _thrownException;

    private string? _keyId;
    private byte[]? _attestationObject1;
    private byte[]? _attestationObject2;
    private byte[]? _challengeHash1;
    private byte[]? _challengeHash2;

    // ── Given ─────────────────────────────────────────────────────────────────

    [Given(@"the SecurityFramework Apple interop is available on this platform")]
    public void GivenSecurityFrameworkAvailable()
    {
        _platformAvailable = OperatingSystem.IsMacOS() || OperatingSystem.IsIOS();

        if (!_platformAvailable)
        {
            Assert.Skip(
                "Native Apple Security.framework attestation requires macOS or iOS. " +
                "Skipping on this platform.");
        }

        _interop = new SecurityFrameworkAppleAttestInterop();
    }

    [Given(@"this test is NOT running on macOS")]
    public void GivenNotRunningOnMacOS()
    {
        if (OperatingSystem.IsMacOS() || OperatingSystem.IsIOS())
        {
            Assert.Skip(
                "This scenario tests non-Apple behaviour; skipping when running on macOS/iOS.");
        }
    }

    // ── When ──────────────────────────────────────────────────────────────────

    [When(@"the provider generates a hardware-backed key via Apple Security\.framework")]
    public async Task WhenGenerateHardwareBackedKey()
    {
        if (!_platformAvailable) return;
        _keyId = await _interop!.GenerateKeyAsync();
    }

    [When(@"the key is attested with a SHA-256 hash of a server challenge")]
    public async Task WhenAttestKeyWithChallenge()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_keyId);

        // Use a deterministic challenge so we can verify the signature in the Then step
        var challenge = Encoding.UTF8.GetBytes("apple-native-attestation-challenge");
        _challengeHash1 = SHA256.HashData(challenge);
        _attestationObject1 = await _interop!.AttestKeyAsync(_keyId, _challengeHash1);
    }

    [When(@"the key is attested with challenge ""(.*)""")]
    public async Task WhenAttestKeyWithNamedChallenge(string challengeText)
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_keyId);

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(challengeText));
        if (_attestationObject1 is null)
        {
            _challengeHash1 = hash;
            _attestationObject1 = await _interop!.AttestKeyAsync(_keyId, hash);
        }
        else
        {
            _challengeHash2 = hash;
            _attestationObject2 = await _interop!.AttestKeyAsync(_keyId, hash);
        }
    }

    [When(@"GenerateKeyAsync is called on SecurityFrameworkAppleAttestInterop")]
    public async Task WhenGenerateKeyCalledOnNonApple()
    {
        using var interop = new SecurityFrameworkAppleAttestInterop();
        try
        {
            await interop.GenerateKeyAsync();
        }
        catch (Exception ex)
        {
            _thrownException = ex;
        }
    }

    // ── Then ──────────────────────────────────────────────────────────────────

    [Then(@"a non-empty keyId is returned from the native call")]
    public void ThenNonEmptyKeyId()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_keyId);
        Assert.NotEmpty(_keyId);
        // KeyId is hex(SHA-256) = 64 hex chars
        Assert.Equal(64, _keyId!.Length);
    }

    [Then(@"the attestation object contains a DER ECDSA signature and an EC public key")]
    public void ThenAttestationObjectHasSignatureAndKey()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_attestationObject1);
        Assert.True(_attestationObject1!.Length > 4, "Attestation object is too short.");

        int sigLen = BitConverter.ToInt32(_attestationObject1, 0);
        Assert.True(sigLen > 0 && sigLen < _attestationObject1.Length - 4,
            $"sigLen={sigLen} is invalid for attestation object of length {_attestationObject1.Length}");

        // DER ECDSA signature starts with 0x30 (SEQUENCE tag)
        Assert.Equal(0x30, _attestationObject1[4]);

        // Public key part: 65-byte uncompressed EC point starting with 0x04
        var pubKeyOffset = 4 + sigLen;
        Assert.True(_attestationObject1.Length - pubKeyOffset == 65,
            $"Expected 65-byte public key, got {_attestationObject1.Length - pubKeyOffset} bytes.");
        Assert.Equal(0x04, _attestationObject1[pubKeyOffset]);
    }

    [Then(@"the ECDSA signature in the attestation object verifies correctly against the challenge hash")]
    public void ThenSignatureVerifies()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_attestationObject1);
        Assert.NotNull(_challengeHash1);

        // Actually verify the ECDSA signature against the challenge hash we stored in the When step
        // This implements Apple's validation step: verify the signature matches the authenticated data
        int sigLen = BitConverter.ToInt32(_attestationObject1!, 0);
        var signatureBytes = _attestationObject1!.AsSpan(4, sigLen).ToArray();

        var pubKeyBytes = _attestationObject1!.AsSpan(4 + sigLen).ToArray();
        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = pubKeyBytes.AsSpan(1, 32).ToArray(),
                Y = pubKeyBytes.AsSpan(33, 32).ToArray()
            }
        };

        using var ecdsa = ECDsa.Create(ecParams);
        bool isValid = ecdsa.VerifyHash(_challengeHash1!, signatureBytes, DSASignatureFormat.Rfc3279DerSequence);
        Assert.True(isValid, "ECDSA signature does not verify against the challenge hash.");
    }

    [Then(@"the two attestation signatures are different")]
    public void ThenSignaturesAreDifferent()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_attestationObject1);
        Assert.NotNull(_attestationObject2);

        int sigLen1 = BitConverter.ToInt32(_attestationObject1!, 0);
        int sigLen2 = BitConverter.ToInt32(_attestationObject2!, 0);
        var sig1 = _attestationObject1!.AsSpan(4, sigLen1);
        var sig2 = _attestationObject2!.AsSpan(4, sigLen2);

        // ECDSA is non-deterministic by default (random k), so same key + different data → different sig
        Assert.False(sig1.SequenceEqual(sig2),
            "Expected two ECDSA signatures of different challenges to differ.");
    }

    [Then(@"a PlatformNotSupportedException is thrown from the native interop")]
    public void ThenPlatformNotSupportedExceptionThrown()
    {
        Assert.NotNull(_thrownException);
        Assert.IsType<PlatformNotSupportedException>(_thrownException);
    }

    public void Dispose() => _interop?.Dispose();
}
