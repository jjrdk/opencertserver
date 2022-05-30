namespace OpenCertServer.Acme.AspNetClient
{
    using System;
    using System.Threading.Tasks;

    public interface ICertificateRenewalLifecycleHook
	{
		Task OnStart();
		Task OnStop();
		Task OnRenewalSucceeded();
		Task OnException(Exception error);
	}
}