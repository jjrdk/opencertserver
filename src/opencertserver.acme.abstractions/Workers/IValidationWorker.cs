namespace OpenCertServer.Acme.Abstractions.Workers
{
    using System.Threading;
    using System.Threading.Tasks;

    public interface IValidationWorker
    {
        Task Run(CancellationToken cancellationToken);
    }
}
