namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Services;
using DnsClient;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

public sealed partial class ValidateDns01Challenges : TokenChallengeValidator, IValidateDns01Challenges
{
    private readonly ILogger<ValidateDns01Challenges> _logger;
    private readonly ILookupClient _client;

    public ValidateDns01Challenges(ILogger<ValidateDns01Challenges> logger, ILookupClient client)
    {
        _logger = logger;
        _client = client;
    }

    protected override string GetExpectedContent(Challenge challenge, Account account)
    {
        var thumbprintBytes = account.Jwk.ComputeJwkThumbprint();
        var thumbprint = Base64UrlEncoder.Encode(thumbprintBytes);

        var keyAuthBytes = Encoding.UTF8.GetBytes($"{challenge.Token}.{thumbprint}");
        var digestBytes = SHA256.HashData(keyAuthBytes);

        var digest = Base64UrlEncoder.Encode(digestBytes);
        return digest;
    }

    protected override async Task<(List<string>? Contents, AcmeError? Error)> LoadChallengeResponse(Challenge challenge, CancellationToken cancellationToken)
    {
        try
        {
            var dnsBaseUrl = challenge.Authorization.Identifier.Value.Replace("*.", "", StringComparison.OrdinalIgnoreCase);
            var dnsRecordName = $"_acme-challenge.{dnsBaseUrl}";
            LogValidatingDnsRecord(dnsRecordName);

            var dnsResponse = await _client.QueryAsync(dnsRecordName, QueryType.TXT, cancellationToken: cancellationToken);
            var contents = new List<string>(dnsResponse.Answers.TxtRecords().SelectMany(x => x.Text));

            return (contents, null);
        }
        catch (DnsResponseException)
        {
            return (null, new AcmeError("dns", "Could not read from DNS"));
        }
    }

    [LoggerMessage(LogLevel.Information, "Validating {dnsRecord}")]
    partial void LogValidatingDnsRecord(string dnsRecord);
}
