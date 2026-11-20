namespace OpenCertServer.Acme.Server.Services;

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Dnsx = DnsClientX;

/// <summary>
/// Resolves DNS records through <see cref="Dnsx.ClientX"/>.
/// </summary>
public sealed class DnsClientXResolver : IDnsResolver
{
    private readonly Dnsx.ClientX _client;

    public DnsClientXResolver(Dnsx.ClientX client)
    {
        _client = client;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<Dnsx.CaaRecord>> ResolveCaaRecordsAsync(
        string name,
        CancellationToken cancellationToken)
        => ResolveTypedAsync<Dnsx.CaaRecord>(name, Dnsx.DnsRecordType.CAA, cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> ResolveTxtRecordsAsync(
        string name,
        CancellationToken cancellationToken)
    {
        var records = await ResolveTypedAsync<Dnsx.TxtRecord>(name, Dnsx.DnsRecordType.TXT, cancellationToken)
            .ConfigureAwait(false);
        return records.Select(record => record.Text).ToList();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<IPAddress>> ResolveIpAddressesAsync(
        string name,
        CancellationToken cancellationToken)
    {
        var aTask = ResolveTypedAsync<Dnsx.ARecord>(name, Dnsx.DnsRecordType.A, cancellationToken);
        var aaaaTask = ResolveTypedAsync<Dnsx.AAAARecord>(name, Dnsx.DnsRecordType.AAAA, cancellationToken);
        await Task.WhenAll(aTask, aaaaTask).ConfigureAwait(false);

        return [.. aTask.Result.Select(r => r.Address), .. aaaaTask.Result.Select(r => r.Address)];
    }

    private async Task<IReadOnlyList<T>> ResolveTypedAsync<T>(
        string name,
        Dnsx.DnsRecordType type,
        CancellationToken cancellationToken)
        where T : class
    {
        var response = await _client
            .Resolve(
                name,
                type,
                requestDnsSec: true,
                typedRecords: true,
                parseTypedTxtRecords: false,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        EnsureSuccessful(response);

        return response.TypedAnswers?.OfType<T>().ToList() ?? [];
    }

    private static void EnsureSuccessful(Dnsx.DnsResponse response)
    {
        if (response.Status is Dnsx.DnsResponseCode.NoError or Dnsx.DnsResponseCode.NXDomain
            && string.IsNullOrEmpty(response.Error))
        {
            return;
        }

        throw new Dnsx.DnsClientException(
            response.Error,
            response);
    }
}
