namespace OpenCertServer.Data;

/// <summary>Connection settings bound from AcmeServer:Relational or Ca:Relational.</summary>
public sealed class RelationalStoreOptions
{
    /// <summary>Connection string for the selected database provider, supplied by a deployment secret provider.</summary>
    public string? Connection { get; set; }
}