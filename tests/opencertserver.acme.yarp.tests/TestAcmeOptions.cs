namespace OpenCertServer.Acme.Yarp.Tests;

using Acme.AspNetClient.Certes;
using CertesSlim.Extensions;

/// <summary>
/// A minimal <see cref="AcmeOptions"/> implementation that points at a loopback ACME server and
/// carries the CSR metadata the renewal engine needs. Used by the per-route tests in place of a
/// live Pebble instance. The required <see cref="AcmeOptions.AccountPassword"/> and
/// <see cref="AcmeOptions.CertificateSigningRequest"/> members are supplied at the call site.
/// </summary>
public sealed class TestAcmeOptions : AcmeOptions
{
      public override Uri AcmeServerUri { get; } = new("http://localhost/directory", UriKind.Absolute);
}
