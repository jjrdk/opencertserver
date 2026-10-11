namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Services;
using CertesSlim.Acme;
using DnsClientX;
using Microsoft.IdentityModel.Tokens;

public sealed class ValidateHttp01Challenges : TokenChallengeValidator, IValidateHttp01Challenges
{
    private readonly HttpClient _httpClient;
    private readonly ICaaValidator _caaValidator;
    private readonly IDnsResolver _dnsResolver;

    public ValidateHttp01Challenges(HttpClient httpClient, ICaaValidator caaValidator, IDnsResolver dnsResolver)
    {
        _httpClient = httpClient;
        _caaValidator = caaValidator;
        _dnsResolver = dnsResolver;
    }

    protected override string GetExpectedContent(Challenge challenge, Account account)
    {
        var thumbprintBytes = account.Jwk.ComputeJwkThumbprint();
        var thumbprint = Base64UrlEncoder.Encode(thumbprintBytes);
        return $"{challenge.Token}.{thumbprint}";
    }

    protected override async Task<(List<string>? Contents, AcmeError? Error)> LoadChallengeResponse(
        Challenge challenge,
        string? accountUri,
        CancellationToken cancellationToken)
    {
        var caaError = await _caaValidator
            .ValidateAsync(challenge.Authorization.Identifier, accountUri, challenge.Type, cancellationToken)
            .ConfigureAwait(false);
        if (caaError != null)
        {
            return (null, caaError);
        }

        // Early blocklist check via the configured DoH resolver — fast-fail before opening a connection.
        IReadOnlyList<IPAddress> resolvedIps;
        try
        {
            resolvedIps = await _dnsResolver
                .ResolveIpAddressesAsync(challenge.Authorization.Identifier.Value, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (DnsClientException)
        {
            return (null,
                new AcmeError
                {
                    Type = "dns",
                    Detail = "Could not resolve challenge host.",
                    Identifier = challenge.Authorization.Identifier
                });
        }

        if (resolvedIps.Count == 0)
        {
            return (null,
                new AcmeError
                {
                    Type = "dns",
                    Detail = "No IP addresses found for challenge host.",
                    Identifier = challenge.Authorization.Identifier
                });
        }

        foreach (var ip in resolvedIps)
        {
            foreach (var range in SsrfBlockingSocketsHandler.ProhibitedRanges)
            {
                if (range.Contains(ip))
                {
                    return (null,
                        new AcmeError
                        {
                            Type = "rejectedIdentifier",
                            Detail = "Challenge target resolves to prohibited address range.",
                            Identifier = challenge.Authorization.Identifier
                        });
                }
            }
        }

        var challengeUrl =
            $"http://{challenge.Authorization.Identifier.Value}/.well-known/acme-challenge/{challenge.Token}";

        try
        {
            // The HttpClient is configured with SsrfBlockingSocketsHandler which:
            //   • resolves the hostname once at connection time (prevents DNS rebinding)
            //   • re-validates the IP at connection time (defence-in-depth)
            //   • does NOT follow redirects (AllowAutoRedirect = false)
            var response = await _httpClient.GetAsync(new Uri(challengeUrl), cancellationToken)
                .ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                return (null,
                    new AcmeError
                    {
                        Type = "incorrectResponse",
                        Detail = $"Got non 200 status code: {response.StatusCode}",
                        Identifier = challenge.Authorization.Identifier
                    });
            }

            var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return ([content], null);
        }
        catch (HttpRequestException ex)
        {
            return (null,
                new AcmeError
                {
                    Type = "connection",
                    Detail = ex.Message,
                    Identifier = challenge.Authorization.Identifier
                });
        }
    }
}

