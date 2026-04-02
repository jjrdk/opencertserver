using System.Diagnostics.CodeAnalysis;

namespace OpenCertServer.Est.Server.Handlers;

/// <summary>
/// Verifies tls-unique proof-of-possession linkage when a request advertises channel-bound proof-of-possession data.
/// </summary>
internal static class TlsUniqueProofOfPossessionVerifier
{
    private const string TlsUniqueMarker = "tls-unique";
    private const string PopFailed = "popFailed";

    private const string ProofOfPossessionExplanation =
        "proof-of-possession verification failed: linking identity and proof-of-possession is required when tls-unique is supplied.";

    public static bool TryVerifyTlsUniqueValue(this string? requestBody, [NotNullWhen(false)] out string? error)
    {
        if (string.IsNullOrWhiteSpace(requestBody) ||
            !requestBody.Contains(TlsUniqueMarker, StringComparison.OrdinalIgnoreCase))
        {
            error = null;
            return true;
        }

        // The server only accepts a tls-unique POP signal when it can verify the channel linkage.
        // Reject unverified tls-unique requests with the EST/CMC popFailed indication.
        error = $"{PopFailed}: {ProofOfPossessionExplanation}";
        return false;
    }
}
