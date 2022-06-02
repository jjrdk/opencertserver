namespace OpenCertServer.Acme.Server.Services
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Abstractions.Model;
    using Abstractions.Services;
    using DnsClient;
    using Microsoft.IdentityModel.Tokens;

    public sealed class Dns01ChallengeValidator : TokenChallengeValidator, IDns01ChallengeValidator
    {
        //private readonly ILogger<Dns01ChallengeValidator> _logger;

        //public Dns01ChallengeValidator(ILogger<Dns01ChallengeValidator> logger)
        //{
        //    _logger = logger;
        //}

        protected override string GetExpectedContent(Challenge challenge, Account account)
        {
            using var sha256 = SHA256.Create();

            var thumbprintBytes = account.Jwk.SecurityKey.ComputeJwkThumbprint();
            var thumbprint = Base64UrlEncoder.Encode(thumbprintBytes);

            var keyAuthBytes = Encoding.UTF8.GetBytes($"{challenge.Token}.{thumbprint}");
            var digestBytes = sha256.ComputeHash(keyAuthBytes);

            var digest = Base64UrlEncoder.Encode(digestBytes);
            return digest;
        }

        protected override async Task<(List<string>? Contents, AcmeError? Error)> LoadChallengeResponse(Challenge challenge, CancellationToken cancellationToken)
        {
            try
            {
                var dnsClient = new LookupClient();
                var dnsBaseUrl = challenge.Authorization.Identifier.Value.Replace("*.", "", StringComparison.OrdinalIgnoreCase);
                var dnsRecordName = $"_acme-challenge.{dnsBaseUrl}";

                var dnsResponse = await dnsClient.QueryAsync(dnsRecordName, QueryType.TXT, cancellationToken: cancellationToken);
                var contents = new List<string>(dnsResponse.Answers.TxtRecords().SelectMany(x => x.Text));

                return (contents, null);
            }
            catch (DnsResponseException)
            {
                return (null, new AcmeError("dns", "Could not read from DNS"));
            }
        }
    }
}
