namespace OpenCertServer.Contrib.Intune;

using System.Net.Http.Headers;

/// <summary>Configuration for the additional Intune enrollment authorization webhook.</summary>
public sealed class DynamicChallengeOptions
{
    /// <summary>The HTTPS webhook endpoint.</summary>
    public required Uri Webhook { get; init; }

    /// <summary>Bearer credential sent to the webhook.</summary>
    public required string Secret { get; init; }

    /// <summary>Maximum time to wait for the webhook.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    internal void Validate()
    {
        if (!Webhook.IsAbsoluteUri || Webhook.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(Webhook.UserInfo) || !string.IsNullOrEmpty(Webhook.Fragment))
        {
            throw new InvalidOperationException("Scep:DynamicChallenge:Webhook must be an absolute HTTPS URL without user info or a fragment.");
        }

        if (string.IsNullOrWhiteSpace(Secret) || Secret.Any(char.IsWhiteSpace)
            || !AuthenticationHeaderValue.TryParse("Bearer " + Secret, out var authorization)
            || authorization.Scheme != "Bearer" || authorization.Parameter != Secret)
        {
            throw new InvalidOperationException("Scep:DynamicChallenge:Secret must be a non-empty bearer credential without whitespace.");
        }

        if (Timeout <= TimeSpan.Zero || Timeout > TimeSpan.FromMinutes(5))
        {
            throw new InvalidOperationException("Scep:DynamicChallenge:Timeout must be between zero and five minutes.");
        }
    }
}
