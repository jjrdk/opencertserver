using CertesSlim.Acme;

namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Services;
using DnsClientX;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

public sealed partial class ValidateDns01Challenges : TokenChallengeValidator, IValidateDns01Challenges
{
    private readonly ILogger<ValidateDns01Challenges> _logger;
    private readonly IDnsResolver _client;
    private readonly ICaaValidator _caaValidator;

    public ValidateDns01Challenges(
        ILogger<ValidateDns01Challenges> logger,
        IDnsResolver client,
        ICaaValidator caaValidator)
    {
        _logger = logger;
        _client = client;
        _caaValidator = caaValidator;
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

    protected override async Task<(List<string>? Contents, AcmeError? Error)> LoadChallengeResponse(
        Challenge challenge,
        string? accountUri,
        CancellationToken cancellationToken)
    {
        try
        {
            var caaError = await _caaValidator
                .ValidateAsync(challenge.Authorization.Identifier, accountUri, challenge.Type, cancellationToken)
                .ConfigureAwait(false);
            if (caaError != null)
            {
                return (null, caaError);
            }

            var dnsBaseUrl =
                challenge.Authorization.Identifier.Value.Replace("*.", "", StringComparison.OrdinalIgnoreCase);
            var dnsRecordName = $"_acme-challenge.{dnsBaseUrl}";
            LogValidatingDnsRecord(dnsRecordName);

            var txtRecords = await _client
                .ResolveTxtRecordsAsync(dnsRecordName, cancellationToken)
                .ConfigureAwait(false);

            return (txtRecords.ToList(), null);
        }
        catch (DnsClientException)
        {
            return (null, new AcmeError { Type = "dns", Detail = "Could not read from DNS" });
        }
    }

    [LoggerMessage(LogLevel.Information, "Validating {dnsRecord}")]
    partial void LogValidatingDnsRecord(string dnsRecord);
}
