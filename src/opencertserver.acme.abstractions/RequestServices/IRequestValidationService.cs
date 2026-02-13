using CertesSlim.Json;

namespace OpenCertServer.Acme.Abstractions.RequestServices;

using System.Threading;
using System.Threading.Tasks;
using HttpModel.Requests;

public interface IRequestValidationService
{
    Task ValidateRequestAsync(
        JwsPayload request,
        AcmeHeader header,
        string requestUrl,
        CancellationToken cancellationToken);
}
