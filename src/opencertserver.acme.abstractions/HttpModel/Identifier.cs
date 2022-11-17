namespace OpenCertServer.Acme.Abstractions.HttpModel;

/// <summary>
/// Defines an identifier as used in orders or authorizations
/// </summary>
public sealed class Identifier
{
    public Identifier(Model.Identifier model)
    {
        if (model is null)
        {
            throw new System.ArgumentNullException(nameof(model));
        }

        Type = model.Type;
        Value = model.Value;
    }

    public string Type { get; }
    public string Value { get; }
}