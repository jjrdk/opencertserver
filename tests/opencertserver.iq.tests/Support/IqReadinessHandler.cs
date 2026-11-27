namespace OpenCertServer.Iq.Tests.Support;

using System.Net.Sockets;

/// <summary>Bounds each HTTP readiness attempt without aborting Testcontainers' readiness loop.</summary>
internal sealed class IqReadinessHandler(HttpMessageHandler innerHandler) : DelegatingHandler(innerHandler)
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            return await base.SendAsync(request, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException exception)
            when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            // Testcontainers 4.16 retries HttpRequestException, but not HTTP timeout cancellations.
            var message = $"HTTP readiness probe timed out: {request.RequestUri}";
            await Console.Error.WriteLineAsync(message);
            throw new HttpRequestException(message, exception);
        }
        catch (SocketException exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var message = $"HTTP readiness probe connection failed: {request.RequestUri}: {exception.Message}";
            await Console.Error.WriteLineAsync(message);
            throw new HttpRequestException(message, exception);
        }
    }
}
