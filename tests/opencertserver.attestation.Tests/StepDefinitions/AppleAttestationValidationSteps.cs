using System.Security.Cryptography;
using System.Text;
using OpenCertServer.Attestation.Native;
using Reqnroll;
using Xunit;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

/// <summary>
/// Validates Apple attestation objects against the Apple validation spec.
/// References: https://apple-docs.everest.mt/docs/devicecheck/attestation-object-validation-guide/
///
/// On macOS: exercises the real <see cref="SecurityFrameworkAppleAttestInterop"/> and verifies
/// the cryptographic correctness of the attestation object (signature, public key, keyId).
/// On non-macOS: scenarios are skipped.
/// </summary>
[Binding]
[Scope(Feature = "Apple Attestation Object Validation (macOS native)")]
public sealed class AppleAttestationValidationSteps : IDisposable
{
    private SecurityFrameworkAppleAttestInterop? _interop;
    private bool _platformAvailable;

    private string? _keyId;
    private byte[]? _attestationObject;
    private byte[]? _attestationObjectForChallenge2;
    private byte[]? _challengeHash;
    private byte[]? _wrongChallengeHash;

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

    // ── When ──────────────────────────────────────────────────────────────────

    [When(@"the provider generates a hardware-backed key via Apple Security\.framework")]
    public async Task WhenGenerateHardwareBackedKey()
    {
        if (!_platformAvailable) return;
        _keyId = await _interop!.GenerateKeyAsync();
    }

    [When(@"the key is attested with a known challenge hash")]
    public async Task WhenAttestKeyWithKnownChallenge()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_keyId);

        // Deterministic challenge so we can re-verify in Then steps
        var challenge = Encoding.UTF8.GetBytes("apple-attest-validation-challenge");
        _challengeHash = SHA256.HashData(challenge);
        _attestationObject = await _interop!.AttestKeyAsync(_keyId, _challengeHash);
    }

    [When(@"the key is attested with two different challenge hashes")]
    public async Task WhenAttestKeyWithTwoDifferentChallenges()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_keyId);

        var challenge1 = Encoding.UTF8.GetBytes("challenge-one");
        _challengeHash = SHA256.HashData(challenge1);
        _attestationObject = await _interop!.AttestKeyAsync(_keyId, _challengeHash);

        var challenge2 = Encoding.UTF8.GetBytes("challenge-two");
        _wrongChallengeHash = SHA256.HashData(challenge2);
        _attestationObjectForChallenge2 = await _interop!.AttestKeyAsync(_keyId, _wrongChallengeHash);
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

    [Then(@"the keyId format matches Apple AppAttest conventions")]
    public void ThenKeyIdMatchesAppleConventions()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_keyId);
        Assert.Equal(64, _keyId!.Length);

        // Verify all characters are valid uppercase hex
        for (int i = 0; i < _keyId!.Length; i++)
        {
            char c = _keyId[i];
            Assert.True(
                (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'),
                $"Invalid hex character at index {i}");
        }
    }

    [Then(
        @"the signature in the attestation object correctly verifies against the challenge using the embedded public key")]
    public void ThenSignatureVerifiesAgainstChallenge()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_attestationObject);
        Assert.NotNull(_challengeHash);

        // Parse signature
        int sigLen = BitConverter.ToInt32(_attestationObject!, 0);
        var signatureBytes = _attestationObject!.AsSpan(4, sigLen).ToArray();

        // Parse public key (X9.62 uncompressed P-256)
        var pubKeyBytes = _attestationObject!.AsSpan(4 + sigLen).ToArray();
        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = pubKeyBytes.AsSpan(1, 32).ToArray(),
                Y = pubKeyBytes.AsSpan(33, 32).ToArray()
            }
        };

        // Verify signature against the challenge hash
        using var ecdsa = ECDsa.Create(ecParams);
        bool isValid = ecdsa.VerifyHash(_challengeHash!, signatureBytes, DSASignatureFormat.Rfc3279DerSequence);
        Assert.True(isValid);
    }

    [Then(@"the attestation object has a valid length-prefixed DER signature at offset 0")]
    public void ThenAttestationObjectHasDerSignatureAtOffset()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_attestationObject);

        // Parse length prefix (4 bytes, little-endian)
        int sigLen = BitConverter.ToInt32(_attestationObject, 0);
        Assert.True(sigLen > 0);
        Assert.True(sigLen < _attestationObject!.Length - 4);

        // DER-encoded signatures start with 0x30 (ASN.1 SEQUENCE tag)
        Assert.Equal(0x30, _attestationObject![4]);
    }

    [Then(@"the attestation object contains a 65-byte X9\.62 uncompressed P-256 public key")]
    public void ThenAttestationObjectHasPublicKey()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_attestationObject);

        // Skip length prefix and signature to get to public key
        int sigLen = BitConverter.ToInt32(_attestationObject, 0);
        int pubKeyOffset = 4 + sigLen;
        int pubKeyLength = _attestationObject!.Length - pubKeyOffset;

        // X9.62 uncompressed P-256 key is 65 bytes: 0x04 || X (32) || Y (32)
        Assert.Equal(65, pubKeyLength);
        Assert.Equal(0x04, _attestationObject![pubKeyOffset]);

        // Verify the key is importable as a valid ECDSA P-256 key
        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = _attestationObject.AsSpan(pubKeyOffset + 1, 32).ToArray(),
                Y = _attestationObject.AsSpan(pubKeyOffset + 33, 32).ToArray()
            }
        };
        // Throws if the key parameters are invalid (e.g., off-curve point)
        using var ecdsa = ECDsa.Create(ecParams);
        Assert.NotNull(ecdsa);
    }

    [Then(@"the two attestation signatures are cryptographically distinct")]
    public void ThenTwoAttestationSignaturesAreDistinct()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_attestationObject);
        Assert.NotNull(_attestationObjectForChallenge2);

        int sigLen1 = BitConverter.ToInt32(_attestationObject!, 0);
        int sigLen2 = BitConverter.ToInt32(_attestationObjectForChallenge2!, 0);

        var sig1 = _attestationObject!.AsSpan(4, sigLen1);
        var sig2 = _attestationObjectForChallenge2!.AsSpan(4, sigLen2);

        // ECDSA uses a random nonce (k), so different challenge hashes produce distinct signatures
        Assert.NotEmpty(sig1.ToArray());
        Assert.NotEmpty(sig2.ToArray());
        Assert.NotEqual(sig1.ToArray(), sig2.ToArray());
    }

    [Then(@"the keyId matches the SHA-256 hash of the attestation public key bytes")]
    public void ThenKeyIdMatchesSha256OfPublicKeyBytes()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_keyId);
        Assert.NotNull(_attestationObject);

        // Parse public key from attestation object
        int sigLen = BitConverter.ToInt32(_attestationObject, 0);
        var pubKeyBytes = _attestationObject!.AsSpan(4 + sigLen).ToArray();

        // Compute SHA-256 of the public key and compare with keyId
        var computedHash = SHA256.HashData(pubKeyBytes);
        var expectedKeyId = Convert.ToHexString(computedHash);

        Assert.Equal(expectedKeyId, _keyId!);
    }

    [Then(@"verifying the attestation against a different challenge hash fails")]
    public void ThenVerifyingAgainstDifferentChallengeFails()
    {
        if (!_platformAvailable) return;
        Assert.NotNull(_attestationObject);
        _wrongChallengeHash ??= SHA256.HashData(Encoding.UTF8.GetBytes("completely-different-challenge"));

        // Parse signature
        int sigLen = BitConverter.ToInt32(_attestationObject!, 0);
        var signatureBytes = _attestationObject!.AsSpan(4, sigLen).ToArray();

        // Parse public key
        var pubKeyBytes = _attestationObject!.AsSpan(4 + sigLen).ToArray();
        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = pubKeyBytes.AsSpan(1, 32).ToArray(),
                Y = pubKeyBytes.AsSpan(33, 32).ToArray()
            }
        };

        // Verify signature against the wrong challenge hash - should fail
        using var ecdsa = ECDsa.Create(ecParams);
        bool isValid = ecdsa.VerifyHash(_wrongChallengeHash, signatureBytes, DSASignatureFormat.Rfc3279DerSequence);
        Assert.False(isValid);
    }

    // ── Cleanup ───────────────────────────────────────────────────────────────

    public void Dispose() => _interop?.Dispose();
}
