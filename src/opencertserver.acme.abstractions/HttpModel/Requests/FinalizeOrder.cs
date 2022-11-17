namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

public sealed class FinalizeOrderRequest
{
    public string? Csr { get; set; }
}