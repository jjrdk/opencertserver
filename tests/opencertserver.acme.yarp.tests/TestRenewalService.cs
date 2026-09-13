namespace OpenCertServer.Acme.Yarp.Tests;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Acme.AspNetClient.Certes;

/// <summary>
/// A test double for <see cref="IAcmeRenewalService"/> that lets a test set the in-memory default
/// leaf and observe Start/Stop, without a running host or a real ACME server.
/// </summary>
internal sealed class TestRenewalService : IAcmeRenewalService
{
     public Uri LetsEncryptUri { get; } = new("http://localhost/directory", UriKind.Absolute);

     public X509Certificate2? Certificate { get; set; }

     public bool StartCalled { get; private set; }

     public bool StopCalled { get; private set; }

        public Task RunOnce(string password)
               => Task.CompletedTask;

        public Task RunAllRoutesOnce(string password, CancellationToken cancellationToken = default)
                => Task.CompletedTask;

        public Task StartAsync(CancellationToken cancellationToken)
              {
             StartCalled = true;
             return Task.CompletedTask;
               }

        public Task StopAsync(CancellationToken cancellationToken)
               {
             StopCalled = true;
             return Task.CompletedTask;
               }

        public void Dispose()
               {
               }
}
