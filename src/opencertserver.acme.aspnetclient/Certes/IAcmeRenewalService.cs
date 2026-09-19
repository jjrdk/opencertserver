namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;

public interface IAcmeRenewalService : IHostedLifecycleService, IDisposable
{
    /// <summary>
    /// The in-memory leaf certificate for the default route (or the most recently renewed route
    /// when no route scope is specified). Preserved for back-compat with Kestrel options.
    /// </summary>
    X509Certificate2? Certificate { get; }
}
