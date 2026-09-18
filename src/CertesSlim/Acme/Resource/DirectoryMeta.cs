namespace CertesSlim.Acme.Resource;

using System.Collections.ObjectModel;
using System.Text.Json.Serialization;

/// <summary>
/// Represents the metadata for a ACME directory.
/// </summary>
public class DirectoryMeta
{
    /// <summary>
    /// Gets or sets the terms of service.
    /// </summary>
    /// <value>
    /// The terms of service.
    /// </value>
    [JsonPropertyName("termsOfService")]
    public string? TermsOfService { get; }

    /// <summary>
    /// Gets or sets the website.
    /// </summary>
    /// <value>
    /// The website.
    /// </value>
    [JsonPropertyName("website")]
    public string? Website { get; }

    /// <summary>
    /// Gets or sets the caa identities.
    /// </summary>
    /// <value>
    /// The caa identities.
    /// </value>
    [JsonPropertyName("caaIdentities")]
    public IList<string> CaaIdentities { get; }

    /// <summary>
    /// Gets or sets a value indicating whether [external account required].
    /// </summary>
    /// <value>
    ///   <c>true</c> if external account required; otherwise, <c>false</c>.
    /// </value>
    [JsonPropertyName("externalAccountRequired")]
    public bool? ExternalAccountRequired { get; }

    /// <summary>
    /// Gets or sets the list of challenge types that include additional content in their responses.
    /// Per RFC 8555 / ACME drafts, advertises which challenge types the server supports beyond standard.
    /// </summary>
    public IReadOnlyList<string>? ChallengeTypesWithAdditionalContent { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryMeta"/> class.
    /// </summary>
    /// <param name="termsOfService">The terms of service.</param>
    /// <param name="website">The website.</param>
    /// <param name="caaIdentities">The caa identities.</param>
    /// <param name="externalAccountRequired">The external account required.</param>
    public DirectoryMeta(
        string? termsOfService,
        string? website,
        IList<string>? caaIdentities,
        bool? externalAccountRequired)
    {
        TermsOfService = termsOfService;
        Website = website;
        CaaIdentities = caaIdentities == null
            ? Array.Empty<string>()
            : new ReadOnlyCollection<string>(caaIdentities);
        ExternalAccountRequired = externalAccountRequired;
    }
}
