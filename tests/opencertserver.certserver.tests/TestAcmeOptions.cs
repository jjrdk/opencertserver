namespace OpenCertServer.CertServer.Tests;

using Acme.AspNetClient.Certes;

public sealed class TestAcmeOptions : AcmeOptions
{
    /// <inheritdoc />
    public override Uri AcmeServerUri { get; } = new Uri("http://localhost/directory", UriKind.Absolute);
}