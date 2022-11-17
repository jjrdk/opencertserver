namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

using System.Diagnostics.CodeAnalysis;

[RequiresUnreferencedCode("Uses unknown types")]
public sealed class AcmePayload<TPayload>
{
    public AcmePayload(TPayload value)
    {
        Value = value;
    }

    public TPayload Value { get; }
}