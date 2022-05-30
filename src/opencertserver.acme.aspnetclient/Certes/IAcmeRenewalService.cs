namespace OpenCertServer.Acme.AspNetClient.Certes
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Hosting;

    public interface IAcmeRenewalService: IHostedService, IDisposable
	{
		Uri LetsEncryptUri { get; }
		Task RunOnce();
	}
}