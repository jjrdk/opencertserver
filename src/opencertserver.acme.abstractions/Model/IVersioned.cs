namespace OpenCertServer.Acme.Abstractions.Model;

/// <summary>
/// Defines a contract for versioned entities, supporting optimistic concurrency control.
/// </summary>
public interface IVersioned
{
    /// <summary>
    /// Gets or sets the concurrency version token.
    /// </summary>
    long Version { get; set; }
}
