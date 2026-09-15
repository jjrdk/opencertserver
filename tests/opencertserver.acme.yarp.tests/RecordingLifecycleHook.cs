namespace OpenCertServer.Acme.Yarp.Tests;

using System;
using System.Threading.Tasks;
using Acme.AspNetClient;

/// <summary>
/// Records the lifecycle events the <see cref="AcmeRenewalService"/> fires, so a test can observe
/// that the renewal thread was started and torn down.
/// </summary>
internal sealed class RecordingLifecycleHook : ICertificateRenewalLifecycleHook
{
    public int StartCount { get; private set; }

    public int StopCount { get; private set; }

    public int RenewalSucceededCount { get; private set; }

    public int ExceptionCount { get; private set; }

    public Task OnStart()
    {
        StartCount++;
        return Task.CompletedTask;
    }

    public Task OnStop()
    {
        StopCount++;
        return Task.CompletedTask;
    }

    public Task OnRenewalSucceeded()
    {
        RenewalSucceededCount++;
        return Task.CompletedTask;
    }

    public Task OnException(Exception error)
    {
        ExceptionCount++;
        return Task.CompletedTask;
    }
}
