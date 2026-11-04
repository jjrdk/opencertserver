namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using Microsoft.Extensions.Logging;

/// <summary>
/// Resolves DNS records through multiple independent Network Perspectives and
/// only returns a result when every perspective agrees.
/// </summary>
/// <remarks>
/// <para>
/// This implements the corroboration requirement of CA/Browser Forum TLS
/// Baseline Requirements §3.2.2.9 for ACME <c>dns-01</c> and <c>http-01</c>
/// validation: each configured DNS-over-HTTPS resolver is queried separately
/// and the answer sets are compared.  A failed perspective or a disagreement
/// between perspectives causes a <see cref="DnsClientException"/> to be thrown,
/// which the challenge validators translate into an invalid challenge.
/// </para>
/// <para>
/// No result is cached between perspectives.  Each perspective issues its own
/// query through its own resolver so that a poisoned cache in one perspective
/// cannot influence another perspective's determination.
/// </para>
/// </remarks>
public sealed partial class MultiPerspectiveDnsResolver : IDnsResolver
{
    private readonly IReadOnlyList<DnsPerspective> _perspectives;
    private readonly ILogger<MultiPerspectiveDnsResolver> _logger;

    public MultiPerspectiveDnsResolver(
        IReadOnlyList<DnsPerspective> perspectives,
        ILogger<MultiPerspectiveDnsResolver> logger)
    {
        ArgumentNullException.ThrowIfNull(perspectives);

        if (perspectives.Count == 0)
        {
            throw new ArgumentException(
                "At least one DNS Network Perspective is required.",
                nameof(perspectives));
        }

        _perspectives = perspectives;
        _logger = logger;
    }

    /// <summary>
    /// Gets the configured Network Perspectives.
    /// </summary>
    public IReadOnlyList<DnsPerspective> Perspectives => _perspectives;

    /// <inheritdoc />
    public Task<IReadOnlyList<CaaRecord>> ResolveCaaRecordsAsync(
        string name,
        CancellationToken cancellationToken)
        => CorroborateAsync(
            name,
            "CAA",
            (resolver, token) => resolver.ResolveCaaRecordsAsync(name, token),
            CanonicalizeCaaRecords,
            cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<string>> ResolveTxtRecordsAsync(
        string name,
        CancellationToken cancellationToken)
        => CorroborateAsync(
            name,
            "TXT",
            (resolver, token) => resolver.ResolveTxtRecordsAsync(name, token),
            CanonicalizeTxtRecords,
            cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<IPAddress>> ResolveIpAddressesAsync(
        string name,
        CancellationToken cancellationToken)
        => CorroborateAsync(
            name,
            "A/AAAA",
            (resolver, token) => resolver.ResolveIpAddressesAsync(name, token),
            CanonicalizeIpAddresses,
            cancellationToken);

    private async Task<IReadOnlyList<T>> CorroborateAsync<T>(
        string name,
        string recordType,
        Func<IDnsResolver, CancellationToken, Task<IReadOnlyList<T>>> resolve,
        Func<IReadOnlyList<T>, string[]> canonicalize,
        CancellationToken cancellationToken)
    {
        var responses = await Task
            .WhenAll(_perspectives.Select(perspective => QueryAsync(perspective, resolve, cancellationToken)))
            .ConfigureAwait(false);

        var failures = responses.Where(response => response.Error is not null).ToArray();
        if (failures.Length > 0)
        {
            foreach (var failure in failures)
            {
                LogPerspectiveFailed(recordType, name, failure.Perspective, failure.Error!.Message);
            }

            var detail = string.Join(
                "; ",
                failures.Select(failure => $"{failure.Perspective}: {failure.Error!.Message}"));
            throw new DnsClientException(
                $"Could not read {recordType} records for '{name}' from all Network Perspectives: {detail}");
        }

        var primary = responses[0];
        var expected = canonicalize(primary.Records!);

        for (var i = 1; i < responses.Length; i++)
        {
            var candidate = responses[i];
            var actual = canonicalize(candidate.Records!);
            if (expected.SequenceEqual(actual, StringComparer.Ordinal))
            {
                continue;
            }

            LogPerspectiveMismatch(
                recordType,
                name,
                primary.Perspective,
                candidate.Perspective,
                string.Join(", ", expected),
                string.Join(", ", actual));

            throw new DnsPerspectiveMismatchException(
                $"The {recordType} response for '{name}' differs between Network Perspectives "
                + $"'{primary.Perspective}' and '{candidate.Perspective}'.",
                _perspectives.Select(perspective => perspective.Name).ToArray());
        }

        return primary.Records!;
    }

    private static async Task<PerspectiveResponse<T>> QueryAsync<T>(
        DnsPerspective perspective,
        Func<IDnsResolver, CancellationToken, Task<IReadOnlyList<T>>> resolve,
        CancellationToken cancellationToken)
    {
        try
        {
            var records = await resolve(perspective.Resolver, cancellationToken).ConfigureAwait(false);
            return new PerspectiveResponse<T>(perspective.Name, records, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            return new PerspectiveResponse<T>(perspective.Name, null, exception);
        }
    }

    private static string[] CanonicalizeCaaRecords(IReadOnlyList<CaaRecord> records)
        => records
            .Select(record => $"{record.Flags}\t{record.Tag?.ToLowerInvariant()}\t{record.Value}")
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

    private static string[] CanonicalizeTxtRecords(IReadOnlyList<string> records)
        => records
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

    private static string[] CanonicalizeIpAddresses(IReadOnlyList<IPAddress> records)
        => records
            .Select(address => address.ToString())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

    private sealed record PerspectiveResponse<T>(
        string Perspective,
        IReadOnlyList<T>? Records,
        Exception? Error);

    [LoggerMessage(
        LogLevel.Warning,
        "DNS {RecordType} lookup for {Name} failed for Network Perspective {Perspective}: {Message}")]
    partial void LogPerspectiveFailed(string recordType, string name, string perspective, string message);

    [LoggerMessage(
        LogLevel.Warning,
        "DNS {RecordType} lookup for {Name} differs between Network Perspectives "
        + "{PrimaryPerspective} [{PrimaryResponse}] and {CandidatePerspective} [{CandidateResponse}]")]
    partial void LogPerspectiveMismatch(
        string recordType,
        string name,
        string primaryPerspective,
        string candidatePerspective,
        string primaryResponse,
        string candidateResponse);
}
