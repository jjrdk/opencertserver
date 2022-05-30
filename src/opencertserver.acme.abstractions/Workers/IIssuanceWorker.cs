namespace OpenCertServer.Acme.Abstractions.Workers
{
    using System.Threading;
    using System.Threading.Tasks;

    public interface IIssuanceWorker
    {
        Task RunAsync(CancellationToken cancellationToken);
    }
}
