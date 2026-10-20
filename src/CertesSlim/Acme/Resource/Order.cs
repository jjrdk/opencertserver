namespace CertesSlim.Acme.Resource;

using System.Text.Json.Serialization;

/// <summary>
/// Represents the ACME Order resource.
/// </summary>
public class Order
{
    /// <summary>
    /// Gets or sets the profile.
    /// </summary>
    public string? Profile { get; set; }

    /// <summary>
    /// Gets or sets the status.
    /// </summary>
    /// <value>
    /// The status.
    /// </value>
    /// <remarks>
    /// See <see cref="OrderStatus"/> for possible values.
    /// </remarks>
    [JsonPropertyName("status")]
    public OrderStatus? Status { get; set; }

    /// <summary>
    /// Gets or sets the expires.
    /// </summary>
    /// <value>
    /// The expires.
    /// </value>
    [JsonPropertyName("expires")]
    public DateTimeOffset? Expires { get; set; }

    /// <summary>
    /// Gets or sets the identifiers.
    /// </summary>
    /// <value>
    /// The identifiers.
    /// </value>
    public IList<Identifier>? Identifiers { get; set; }

    /// <summary>
    /// Gets or sets the not before.
    /// </summary>
    /// <value>
    /// The not before.
    /// </value>
    [JsonPropertyName("notBefore")]
    public DateTimeOffset? NotBefore { get; set; }

    /// <summary>
    /// Gets or sets the not after.
    /// </summary>
    /// <value>
    /// The not after.
    /// </value>
    [JsonPropertyName("notAfter")]
    public DateTimeOffset? NotAfter { get; set; }

    /// <summary>
    /// Gets or sets the error.
    /// </summary>
    /// <value>
    /// The error.
    /// </value>
    [JsonPropertyName("error")]
    public ErrorDetails? Error { get; set; }

    /// <summary>
    /// Gets or sets the authorizations.
    /// </summary>
    /// <value>
    /// The authorizations.
    /// </value>
    [JsonPropertyName("authorizations")]
    public IList<Uri>? Authorizations { get; set; }

    /// <summary>
    /// Gets or sets the finalize.
    /// </summary>
    /// <value>
    /// The finalize.
    /// </value>
    [JsonPropertyName("finalize")]
    public Uri? Finalize { get; set; }

    /// <summary>
    /// Gets or sets the certificate.
    /// </summary>
    /// <value>
    /// The certificate.
    /// </value>
    [JsonPropertyName("certificate")]
    public Uri? Certificate { get; set; }

    /// <summary>
    /// Represents the payload to finalize an order.
    /// </summary>
    /// <seealso cref="Order" />
    internal class OrderPayload : Order
    {
        /// <summary>
        /// Gets or sets the CSR.
        /// </summary>
        /// <value>
        /// The CSR.
        /// </value>
        [JsonPropertyName("csr")]
        public required string Csr { get; set; }
    }
}