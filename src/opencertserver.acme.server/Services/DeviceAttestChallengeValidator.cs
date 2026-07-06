namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Services;
using OpenCertServer.Tpm2Lib;

/// <summary>
/// Validates device-attest-01 ACME challenges by verifying attestation evidence.
/// Checks: nonce match → TPM quote structure → AIK signature → AIK certificate chain.
/// See: https://smallstep.com/blog/build-your-own-device-identity-solution/
/// </summary>
public sealed class DeviceAttestChallengeValidator : IValidateDeviceAttestChallenges, IDisposable
{
    private readonly IAttestationTrustProvider _trustProvider;

    // S-III: Track consumed nonces to prevent replay attacks.
    // Key = nonce token (base64url), Value = time consumed.
    private readonly ConcurrentDictionary<string, DateTimeOffset> _consumedNonces = new();

    // Periodically prune stale nonce entries to prevent unbounded memory growth.
    private static readonly TimeSpan NonceTtl = TimeSpan.FromMinutes(5);
    private readonly Timer _cleanupTimer;

    public DeviceAttestChallengeValidator(IAttestationTrustProvider trustProvider)
    {
        _trustProvider = trustProvider;
        _cleanupTimer = new Timer(PruneExpiredNonces, null, NonceTtl, NonceTtl);
    }

    private void PruneExpiredNonces(object? state)
    {
        var cutoff = DateTimeOffset.UtcNow - NonceTtl;
        foreach (var key in _consumedNonces.Keys)
        {
            if (_consumedNonces.TryGetValue(key, out var consumed) && consumed < cutoff)
                _consumedNonces.TryRemove(new KeyValuePair<string, DateTimeOffset>(key, consumed));
        }
    }

    public void Dispose() => _cleanupTimer.Dispose();

    public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
        Challenge challenge,
        Account account,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(account);

        var rawBody = challenge.ExtraData;
        if (string.IsNullOrEmpty(rawBody))
        {
            return Task.FromResult<(bool IsValid, AcmeError? error)>((false,
                new AcmeError("device_attestation", "No attestation proof provided in challenge body")));
        }

        DeviceAttestChallengeAnswer? answer;
        try
        {
            answer = JsonSerializer.Deserialize(rawBody,
                AcmeSerializerContext.Default.DeviceAttestChallengeAnswer);
        }
        catch (JsonException)
        {
            return Task.FromResult<(bool IsValid, AcmeError? error)>((false,
                new AcmeError("malformed", "Unable to parse device attestation proof")));
        }

        if (answer == null)
        {
            return Task.FromResult<(bool IsValid, AcmeError? error)>((false,
                new AcmeError("malformed", "Unable to parse device attestation proof")));
        }

        // Step 1: Verify nonce matches challenge token.
        if (!Base64UrlBytesEqual(answer.Nonce, challenge.Token))
        {
            return Task.FromResult<(bool IsValid, AcmeError? error)>((false,
                new AcmeError("invalid_nonce", "Attestation nonce does not match challenge nonce")));
        }

        // S-III: Reject replayed nonces.
        if (!_consumedNonces.TryAdd(challenge.Token, DateTimeOffset.UtcNow))
        {
            return Task.FromResult<(bool IsValid, AcmeError? error)>((false,
                new AcmeError("replay_nonce", "This attestation nonce has already been consumed")));
        }

        // Step 2: Verify the AIK certificate chain against trusted roots (S-II).
        if (!VerifyAikCertificateChain(answer.AikCertificate))
        {
            return Task.FromResult<(bool IsValid, AcmeError? error)>((false,
                new AcmeError("invalid_attestation", "Device attestation chain verification failed")));
        }

        // Step 3: Verify the TPM proof structure and AIK signature (S-I).
        if (!VerifyProof(answer, challenge.Token))
        {
            return Task.FromResult<(bool IsValid, AcmeError? error)>((false,
                new AcmeError("invalid_attestation", "Device attestation proof verification failed")));
        }

        return Task.FromResult<(bool IsValid, AcmeError? error)>((true, null));
    }

    // ─── Chain verification (S-II) ────────────────────────────────────────────

    /// <summary>
    /// Verifies the AIK cert chain against injected manufacturer trusted roots.
    /// <see cref="X509VerificationFlags.AllowUnknownCertificateAuthority"/> is intentionally
    /// absent — self-signed or unrecognised CA certs are rejected.
    /// </summary>
    private bool VerifyAikCertificateChain(string? aikCertB64Url)
    {
        if (string.IsNullOrEmpty(aikCertB64Url))
            return false;

        var aikBytes = TryDecodeBase64Url(aikCertB64Url);
        if (aikBytes == null)
            return false;

        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(aikBytes);
            using var chain = new X509Chain();

            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            var roots = _trustProvider.GetTrustedRoots();
            if (roots.Count > 0)
            {
                // Use custom trust mode so only injected roots are authoritative.
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.AddRange(roots);
            }
            else
            {
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.System;
            }

            return chain.Build(cert);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    // ─── Proof verification (S-I) ─────────────────────────────────────────────

    /// <summary>
    /// Verifies the TPM quote proof:
    /// 1. Decodes and parses the Tpm2bAttest wire bytes.
    /// 2. Confirms magic = <see cref="Generated.Value"/> and type = AttestQuote.
    /// 3. Confirms extraData matches the challenge token bytes (anti-replay within the quote).
    /// 4. Verifies the AIK signature over the proof bytes.
    /// </summary>
    private bool VerifyProof(DeviceAttestChallengeAnswer answer, string challengeToken)
    {
        if (string.IsNullOrEmpty(answer.Proof))
            return false;

        var proofBytes = TryDecodeBase64Url(answer.Proof);
        if (proofBytes == null || proofBytes.Length == 0)
            return false;

        // Parse the Tpm2bAttest (size-prefixed TPMS_ATTEST) structure.
        Tpm2bAttest tpm2bAttest;
        try
        {
            tpm2bAttest = Marshaller.FromTpmRepresentation<Tpm2bAttest>(proofBytes);
        }
        catch (Exception ex) when (ex is TpmException or ArgumentOutOfRangeException
                                      or IndexOutOfRangeException or OverflowException)
        {
            return false;
        }

        var attest = tpm2bAttest.attestationData;

        // Check TPM magic constant (0xff544347 = TPM_GENERATED_VALUE).
        if (attest.magic != Generated.Value)
            return false;

        // Check attestation type is Quote (not Certify, Time, NV, etc.).
        if (attest.attested is not QuoteInfo)
            return false;

        // Verify the nonce embedded in extraData matches the challenge token bytes.
        var expectedNonce = TryDecodeBase64Url(challengeToken);
        if (expectedNonce == null)
            return false;

        if (!expectedNonce.AsSpan().SequenceEqual(attest.extraData ?? []))
            return false;

        // Verify the AIK signature over the proof bytes.
        return VerifyAikSignature(proofBytes, answer.Signature, answer.AikCertificate);
    }

    /// <summary>
    /// Verifies that <paramref name="signatureB64Url"/> is a valid RSA-PKCS1v15-SHA256
    /// signature over <paramref name="proofBytes"/> using the public key in the AIK certificate.
    /// </summary>
    private static bool VerifyAikSignature(byte[] proofBytes, string? signatureB64Url, string? aikCertB64Url)
    {
        if (string.IsNullOrEmpty(signatureB64Url) || string.IsNullOrEmpty(aikCertB64Url))
            return false;

        var sigBytes = TryDecodeBase64Url(signatureB64Url);
        var aikBytes = TryDecodeBase64Url(aikCertB64Url);
        if (sigBytes == null || aikBytes == null)
            return false;

        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(aikBytes);
            using var rsa = cert.GetRSAPublicKey();
            if (rsa == null)
                return false;

            return rsa.VerifyData(proofBytes, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    // ─── Base64url helpers ────────────────────────────────────────────────────

    private static bool Base64UrlBytesEqual(ReadOnlySpan<char> a, ReadOnlySpan<char> b)
    {
        var bytesA = TryDecodeBase64Url(a);
        var bytesB = TryDecodeBase64Url(b);
        return bytesA != null && bytesB != null && bytesA.AsSpan().SequenceEqual(bytesB);
    }

    private static byte[]? TryDecodeBase64Url(ReadOnlySpan<char> input)
    {
        try
        {
            return Convert.FromBase64String(PadBase64Url(input));
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string PadBase64Url(ReadOnlySpan<char> input)
    {
        var s = new string(input).Replace('-', '+').Replace('_', '/');
        return (s.Length % 4) switch
        {
            2 => s + "==",
            3 => s + "=",
            _ => s
        };
    }
}
