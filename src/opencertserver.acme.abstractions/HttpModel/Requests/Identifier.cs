namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests
{
    /// <summary>
    /// Defines an identifier as used in orders or authorizations
    /// </summary>
    public sealed class Identifier
    {
        public string? Type { get; set; }
        public string? Value { get; set; }
    }
}
