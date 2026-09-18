namespace CertesSlim.Acme.Resource;

using System.Text.Json.Serialization;

/// <summary>
/// Represents the status for <see cref="Challenge"/>.
/// </summary>
public enum ChallengeStatus
{
    /// <summary>
    /// The pending status.
    /// </summary>
    [JsonPropertyName("pending")] Pending,

    /// <summary>
    /// The processing status.
    /// </summary>
    [JsonPropertyName("processing")] Processing,

    /// <summary>
    /// The valid status.
    /// </summary>
    [JsonPropertyName("valid")] Valid,

    /// <summary>
    /// The invalid status.
    /// </summary>
    [JsonPropertyName("invalid")] Invalid
}
