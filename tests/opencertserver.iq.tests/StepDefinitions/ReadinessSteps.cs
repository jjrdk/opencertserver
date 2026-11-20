namespace OpenCertServer.Iq.Tests.StepDefinitions;

using System.Net;
using System.Net.Sockets;
using OpenCertServer.Iq.Tests.Support;
using Reqnroll;
using Xunit;

[Binding]
[Scope(Feature = "IQ readiness probes recover from transient timeouts")]
public sealed class ReadinessSteps
{
    private readonly ReadinessTransport _transport = new();
    private HttpRequestException? _failure;
    private OperationCanceledException? _cancellation;
    private HttpStatusCode _status;

    [Given("a readiness transport that stalls its first request")]
    public void StallFirstRequest() => _transport.StallFirstRequest = true;

    [Given("a readiness transport with a socket error on its first request")]
    public void FailFirstRequest() => _transport.FailFirstRequest = true;

    [When("the stalled readiness attempt is retried")]
    [When("the socket readiness attempt is retried")]
    public async Task Retry()
    {
        using var invoker = new HttpMessageInvoker(new IqReadinessHandler(_transport));
        using var first = new HttpRequestMessage(HttpMethod.Get, "https://localhost/health");
        _failure = await Assert.ThrowsAsync<HttpRequestException>(() =>
            invoker.SendAsync(first, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(15)));
        using var second = new HttpRequestMessage(HttpMethod.Get, "https://localhost/health");
        using var response = await invoker.SendAsync(second, CancellationToken.None);
        _status = response.StatusCode;
    }

    [Then("the timeout is reported as a retryable HTTP failure")]
    public void RetryableTimeout()
    {
        Assert.NotNull(_failure);
        Assert.IsAssignableFrom<OperationCanceledException>(_failure.InnerException);
        Assert.Contains("/health", _failure.Message, StringComparison.Ordinal);
    }

    [Then("the socket error is reported as a retryable HTTP failure")]
    public void RetryableSocketError()
    {
        Assert.NotNull(_failure);
        Assert.Equal(SocketError.InvalidArgument,
            Assert.IsType<SocketException>(_failure.InnerException).SocketErrorCode);
        Assert.Contains("/health", _failure.Message, StringComparison.Ordinal);
    }

    [Then("the next readiness attempt succeeds")]
    public void RetrySucceeded()
    {
        Assert.Equal(2, _transport.Attempts);
        Assert.Equal(HttpStatusCode.OK, _status);
    }

    [When("the caller cancels a readiness attempt")]
    public async Task Cancel()
    {
        using var invoker = new HttpMessageInvoker(new IqReadinessHandler(_transport));
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost/health");
        _cancellation = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            invoker.SendAsync(request, cancellation.Token));
    }

    [Then("caller cancellation is preserved")]
    public void CancellationPreserved() => Assert.NotNull(_cancellation);

    [Given("a readiness transport returning HTTP {int}")]
    public void ConfigureStatus(int status) => _transport.Status = (HttpStatusCode)status;

    [When("the readiness response is received")]
    public async Task ReceiveResponse()
    {
        using var invoker = new HttpMessageInvoker(new IqReadinessHandler(_transport));
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost/health");
        using var response = await invoker.SendAsync(request, CancellationToken.None);
        _status = response.StatusCode;
    }

    [Then("the readiness response still has HTTP {int}")]
    public void StatusPreserved(int status)
    {
        Assert.Equal(1, _transport.Attempts);
        Assert.Equal((HttpStatusCode)status, _status);
    }

    private sealed class ReadinessTransport : HttpMessageHandler
    {
        public bool StallFirstRequest { get; set; }
        public bool FailFirstRequest { get; set; }
        public int Attempts { get; private set; }
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (++Attempts == 1)
            {
                if (FailFirstRequest)
                {
                    throw new SocketException((int)SocketError.InvalidArgument);
                }
                if (StallFirstRequest)
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                }
            }
            return new HttpResponseMessage(Status);
        }
    }
}
