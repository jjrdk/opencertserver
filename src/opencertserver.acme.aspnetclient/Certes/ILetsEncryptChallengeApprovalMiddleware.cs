namespace OpenCertServer.Acme.AspNetClient.Certes
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;

    public interface ILetsEncryptChallengeApprovalMiddleware
	{
		Task Invoke(HttpContext context);
	}
}