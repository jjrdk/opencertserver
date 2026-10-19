namespace CertesSlim.Acme;

using System.Text.Json.Serialization;
using System.Net;
using CertesSlim.Acme.Resource;

/// <summary>
/// Represents an error returned from an ACME server.
/// </summary>
public class AcmeError
{
    /// <summary>
    /// Gets or sets the error type URI.
    /// </summary>
    /// <value>
    /// The error type URI.
    /// </value>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Type
    {
        get;
        set { field = value == null || value.Contains(':') ? value : $"urn:ietf:params:acme:error:{value}"; }
    }

    /// <summary>
    /// Gets or sets the detail message.
    /// </summary>
    /// <value>
    /// The detail message.
    /// </value>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detail { get; set; }

    /// <summary>
    /// Gets or sets the identifier for this error.
    /// </summary>
    /// <value>
    /// The identifier for this error.
    /// </value>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Identifier? Identifier { get; set; }

    /// <summary>
    /// Gets or sets the subproblems.
    /// </summary>
    /// <value>
    /// The subproblems.
    /// </value>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IList<AcmeError>? Subproblems { get; set; }

    /// <summary>
    /// Gets or sets the HTTP status.
    /// </summary>
    /// <value>
    /// The HTTP status.
    /// </value>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public HttpStatusCode? Status { get; set; }
}
