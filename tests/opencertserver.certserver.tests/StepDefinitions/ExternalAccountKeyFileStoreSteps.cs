namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Diagnostics;
using Microsoft.Extensions.Options;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Server.Configuration;
using OpenCertServer.Acme.Server.Stores;
using Reqnroll;
using Xunit;

[Binding]
public sealed class ExternalAccountKeyFileStoreSteps : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "eab-store-" + Guid.NewGuid().ToString("N"));
    private ExternalAccountKeyStore _store = null!;
    private ExternalAccountKey _key = null!;
    private string _path = null!;

    [Given("a provisioned external account key in a file store")]
    public async Task GivenAKey()
    {
        var options = Options.Create(new FileStoreOptions { BasePath = _directory });
        _store = new ExternalAccountKeyStore(options);
        _key = new ExternalAccountKey("eab-key", "secret");
        await _store.SaveKey(_key, CancellationToken.None);
        _path = Path.Combine(options.Value.ExternalAccountKeyPath, _key.KeyId, "key.json");
        Assert.Contains("eab-key", await File.ReadAllTextAsync(_path));
    }

    [Then("all file store operations wait for an exclusive file holder")]
    public async Task OperationsWaitForExclusiveHolder()
    {
        await WaitForRelease(() => _store.LoadKey(_key.KeyId, CancellationToken.None));
        _key = (await _store.LoadKey(_key.KeyId, CancellationToken.None))!;
        await WaitForRelease(() => _store.SaveKey(_key, CancellationToken.None));
        await WaitForRelease(() => _store.TryConsumeKey(_key.KeyId, "account", CancellationToken.None));
        var loaded = await _store.LoadKey(_key.KeyId, CancellationToken.None);
        Assert.True(loaded!.IsUsed);
        Assert.Equal("account", loaded.BoundAccountId);
        await Assert.ThrowsAsync<ConcurrencyException>(() => _store.SaveKey(_key, CancellationToken.None));
        Assert.False(await _store.TryConsumeKey(_key.KeyId, "another", CancellationToken.None));
    }

    private async Task WaitForRelease(Func<Task> operation)
    {
        await using var held = File.Open(_path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var pending = operation();
        await Task.Delay(100);
        Assert.False(pending.IsCompleted);
        await held.DisposeAsync();
        await pending.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Then("locked file retries are bounded and cancellation is honored")]
    public async Task RetriesAreBounded()
    {
        await using var held = File.Open(_path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Func<CancellationToken, Task>[] operations =
        [
            token => _store.LoadKey(_key.KeyId, token),
            token => _store.SaveKey(_key, token),
            token => _store.TryConsumeKey(_key.KeyId, "account", token)
        ];
        foreach (var operation in operations)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation(cts.Token));
            var stopwatch = Stopwatch.StartNew();
            await Assert.ThrowsAsync<IOException>(() => operation(CancellationToken.None));
            Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(250), TimeSpan.FromSeconds(5));
        }
    }

    [Then("concurrent stores preserve versioning and only one consumer wins")]
    public async Task ConcurrentOperations()
    {
        var other = new ExternalAccountKeyStore(Options.Create(new FileStoreOptions { BasePath = _directory }));
        var first = (await _store.LoadKey(_key.KeyId, CancellationToken.None))!;
        var second = (await other.LoadKey(_key.KeyId, CancellationToken.None))!;
        var saves = new[] { _store.SaveKey(first, CancellationToken.None), other.SaveKey(second, CancellationToken.None) };
        try
        {
            await Task.WhenAll(saves);
        }
        catch (ConcurrencyException)
        {
            // Inspect both outcomes below.
        }
        _ = Assert.Single(saves, task => task.IsCompletedSuccessfully);
        _ = Assert.Single(saves, task => task.Exception?.InnerException is ConcurrencyException);
        var consumes = await Task.WhenAll(
            _store.TryConsumeKey(_key.KeyId, "first", CancellationToken.None),
            other.TryConsumeKey(_key.KeyId, "second", CancellationToken.None));
        Assert.Single(consumes, won => won);
        Assert.True((await other.LoadKey(_key.KeyId, CancellationToken.None))!.IsUsed);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
