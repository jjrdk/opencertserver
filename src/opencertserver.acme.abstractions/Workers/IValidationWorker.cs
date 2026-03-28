namespace OpenCertServer.Acme.Abstractions.Workers;

using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Defines a background worker for processing ACME challenge validations.
/// </summary>
public interface IValidationWorker
{
    /// <summary>
    /// Runs the validation worker asynchronously.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task Run(CancellationToken cancellationToken);
}
