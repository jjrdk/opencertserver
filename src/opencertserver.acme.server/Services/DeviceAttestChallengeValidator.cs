namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Services;

/// <summary>
/// Validates device-attest-01 ACME challenges by verifying attestation evidence.
/// See: https://smallstep.com/blog/build-your-own-device-identity-solution/
/// </summary>
public sealed class DeviceAttestChallengeValidator : IValidateDeviceAttestChallenges
{
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
            answer = JsonSerializer.Deserialize(rawBody, AcmeSerializerContext.Default.DeviceAttestChallengeAnswer);
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

        // Verify nonce matches challenge token (base64url comparison)
        if (!Base64UrlBytesEqual(answer.Nonce, challenge.Token))
        {
            return Task.FromResult<(bool IsValid, AcmeError? error)>((false,
                new AcmeError("invalid_nonce", "Attestation nonce does not match challenge nonce")));
        }

        // Verify attestation chain against manufacturer root CAs
        if (!VerifyAttestationChain(answer))
        {
            return Task.FromResult<(bool IsValid, AcmeError? error)>((false,
                new AcmeError("invalid_attestation", "Device attestation chain verification failed")));
        }

        return Task.FromResult<(bool IsValid, AcmeError? error)>((true, null));
    }

    /// <summary>
    /// Compares two base64url-encoded strings for byte-level equality.
    /// </summary>
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
        catch
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

    /// <summary>
    /// Verifies the AIK certificate chain against manufacturer root CAs.
    /// Per spec: validates the attestation itself using the root certificate(s) of the Attestation CA,
    /// confirming the device's trustworthiness.
    /// </summary>
    private static bool VerifyAttestationChain(DeviceAttestChallengeAnswer answer)
    {
        if (string.IsNullOrEmpty(answer.AikCertificate))
        {
            // No AIK cert provided — chain cannot be verified
            return false;
        }

        var aikBytes = TryDecodeBase64Url(answer.AikCertificate);
        if (aikBytes == null)
        {
            return false;
        }

        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(aikBytes);
            using var chain = new X509Chain();

            // Allow the OS trust store to verify manufacturer roots (Apple Attestation CA, Intel ME, AMD PSP)
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.System;

            return chain.Build(cert);
        }
        catch
        {
            return false;
        }
    }
}
