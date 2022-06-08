namespace OpenCertServer.Acme.Abstractions.RequestServices
{
    using System.Threading;
    using System.Threading.Tasks;
    using HttpModel.Requests;

    public interface IRequestValidationService
    {
        Task ValidateRequestAsync(
            AcmeRawPostRequest request,
            AcmeHeader header,
            string requestUrl,
            CancellationToken cancellationToken);
    }
}
