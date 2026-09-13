namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;

public interface IAcmeRenewalService : IHostedService, IDisposable
{
     Uri LetsEncryptUri { get; }

     Task RunOnce(string password);

    /// <summary>
    /// The in-memory leaf certificate for the default route (or the most recently renewed route
    /// when no route scope is specified). Preserved for back-compat with Kestrel options.
    /// </summary>
     X509Certificate2? Certificate { get; }

      /// <summary>
      /// Runs a single renewal pass for every registered ACME route. A failure on one route does
      /// not block the others; each route's outcome is returned.
      /// </summary>
      Task RunAllRoutesOnce(string password, CancellationToken cancellationToken = default);
}
