namespace OpenCertServer.Acme.Server.Services;

using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;

/// <summary>
/// Resolves DNS records through <see cref="ClientX"/>.
/// </summary>
public sealed class DnsClientXResolver : IDnsResolver
{
    private readonly ClientX _client;

    public DnsClientXResolver(ClientX client)
    {
        _client = client;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<CaaRecord>> ResolveCaaRecordsAsync(
        string name,
        CancellationToken cancellationToken)
        => ResolveTypedAsync<CaaRecord>(name, DnsRecordType.CAA, cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> ResolveTxtRecordsAsync(
        string name,
        CancellationToken cancellationToken)
    {
        var records = await ResolveTypedAsync<TxtRecord>(name, DnsRecordType.TXT, cancellationToken)
            .ConfigureAwait(false);
        return records.Select(record => record.Text).ToList();
    }

    private async Task<IReadOnlyList<T>> ResolveTypedAsync<T>(
        string name,
        DnsRecordType type,
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

    private static void EnsureSuccessful(DnsResponse response)
    {
        if (response.Status is DnsResponseCode.NoError or DnsResponseCode.NXDomain
            && string.IsNullOrEmpty(response.Error))
        {
            return;
        }

        throw new DnsClientException(
            response.Error ?? $"DNS query failed with status {response.Status}.",
            response);
    }
}