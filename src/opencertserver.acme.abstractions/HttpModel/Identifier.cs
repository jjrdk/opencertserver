namespace OpenCertServer.Acme.Abstractions.HttpModel;

/// <summary>
/// Defines an identifier as used in orders or authorizations.
/// </summary>
public sealed class Identifier
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Identifier"/> class from a model identifier.
    /// </summary>
    /// <param name="model">The model identifier.</param>
    public Identifier(Model.Identifier model)
    {
        if (model is null)
        {
            throw new ArgumentNullException(nameof(model));
        }

        Type = model.Type;
        Value = model.Value;
    }

    /// <summary>
    /// Gets the identifier type (e.g., dns, ip).
    /// </summary>
    public string Type { get; }
    /// <summary>
    /// Gets the identifier value (e.g., domain name).
    /// </summary>
    public string Value { get; }
}
