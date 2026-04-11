using CertesSlim.Json;
using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Server.RequestServices;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.HttpModel.Requests;
using Abstractions.Model;
using Abstractions.RequestServices;
using Abstractions.Services;
using Abstractions.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

public sealed class DefaultRequestValidationService : IRequestValidationService
{
    private readonly IAccountService _accountService;
    private readonly INonceStore _nonceStore;

    private readonly ILogger<DefaultRequestValidationService> _logger;

    private static readonly HashSet<string> SupportedAlgs =
    [
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512"
    ];

    private static readonly HashSet<string> KidOnlyEndpoints =
    [
        "Account",
        "OrderList",
        "NewOrder",
        "GetOrder",
        "GetAuthorization",
        "AcceptChallenge",
        "FinalizeOrder",
        "GetCertificate",
        "KeyChange"
    ];

    private static readonly HashSet<string> EmptyPayloadOnlyEndpoints =
    [
        "OrderList",
        "GetOrder",
        "GetCertificate"
    ];

    public DefaultRequestValidationService(IAccountService accountService, INonceStore nonceStore,
        ILogger<DefaultRequestValidationService> logger)
    {
        _accountService = accountService;
        _nonceStore = nonceStore;
        _logger = logger;
    }

    public async Task ValidateRequestAsync(JwsPayload request, AcmeHeader header,
        string requestUrl, string? requestContentType, string? endpointName, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        ArgumentNullException.ThrowIfNull(header);

        if (string.IsNullOrWhiteSpace(requestUrl))
        {
            throw new ArgumentNullException(nameof(requestUrl));
        }

        ValidateRequestEnvelope(request);
        ValidateRequestContentType(requestContentType);
        ValidateRequestHeader(header, requestUrl, endpointName);
        ValidateRequestPayloadSemantics(request, endpointName);
        await ValidateNonceAsync(header.Nonce, cancellationToken).ConfigureAwait(false);
        await ValidateSignatureAsync(request, header, cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateRequestEnvelope(JwsPayload request)
    {
        if (string.IsNullOrWhiteSpace(request.Protected))
        {
            throw new MalformedRequestException("The JWS protected header was empty.");
        }

        if (request.Payload == null)
        {
            throw new MalformedRequestException("The JWS payload was missing.");
        }

        if (string.IsNullOrWhiteSpace(request.Signature))
        {
            throw new MalformedRequestException("The JWS signature was empty.");
        }
    }

    private static void ValidateRequestContentType(string? requestContentType)
    {
        var mediaType = requestContentType?.Split(';', 2, StringSplitOptions.TrimEntries)[0];
        if (!string.Equals(mediaType, "application/jose+json", StringComparison.OrdinalIgnoreCase))
        {
            throw new MalformedRequestException("ACME POST requests must use the application/jose+json media type.");
        }
    }

    private void ValidateRequestHeader(AcmeHeader header, string requestUrl, string? endpointName)
    {
        ArgumentNullException.ThrowIfNull(header);

        _logger.LogDebug("Attempting to validate AcmeHeader ...");

        if (string.IsNullOrWhiteSpace(header.Url))
        {
            throw new MalformedRequestException("Header Url was empty.");
        }

        if (!Uri.IsWellFormedUriString(header.Url, UriKind.RelativeOrAbsolute))
        {
            throw new MalformedRequestException("Header Url is not well-formed.");
        }

        if (header.Url != requestUrl)
        {
            throw new NotAuthorizedException();
        }

        if (string.IsNullOrWhiteSpace(header.Alg))
        {
            throw new MalformedRequestException("Header Alg was empty.");
        }

        if (!SupportedAlgs.Contains(header.Alg))
        {
            throw new BadSignatureAlgorithmException();
        }

        if (header is { Jwk: not null, Kid: not null })
        {
            throw new MalformedRequestException("Do not provide both Jwk and Kid.");
        }

        if (header.Jwk == null && header.Kid == null)
        {
            throw new MalformedRequestException("Provide either Jwk or Kid.");
        }

        ValidateEndpointKeyIdentifierRules(header, endpointName);

        _logger.LogDebug("successfully validated AcmeHeader");
    }

    private static void ValidateEndpointKeyIdentifierRules(AcmeHeader header, string? endpointName)
    {
        if (string.Equals(endpointName, "NewAccount", StringComparison.Ordinal))
        {
            if (header.Jwk == null || header.Kid != null)
            {
                throw new MalformedRequestException("newAccount requests must be signed with a JWK and must not contain a Kid.");
            }


            return;
        }

        if (endpointName != null && KidOnlyEndpoints.Contains(endpointName) && (header.Kid == null || header.Jwk != null))
        {
            throw new MalformedRequestException("Existing-account ACME requests must be signed with a Kid and must not contain a JWK.");
        }
    }

    private static void ValidateRequestPayloadSemantics(JwsPayload request, string? endpointName)
    {
        if (endpointName != null && EmptyPayloadOnlyEndpoints.Contains(endpointName) && !string.IsNullOrEmpty(request.Payload))
        {
            throw new MalformedRequestException("POST-as-GET requests to this ACME resource must use the empty string as the JWS payload.");
        }
    }

    private async Task ValidateNonceAsync(string? nonce, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Attempting to validate replay nonce ...");
        if (string.IsNullOrWhiteSpace(nonce))
        {
            _logger.LogDebug($"Nonce was empty.");
            throw new BadNonceException();
        }

        if (!await _nonceStore.TryRemoveNonceAsync(new Nonce(nonce), cancellationToken).ConfigureAwait(false))
        {
            _logger.LogDebug($"Nonce was invalid.");
            throw new BadNonceException();
        }

        _logger.LogDebug("successfully validated replay nonce");
    }

    private async Task ValidateSignatureAsync(JwsPayload request, AcmeHeader header, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        ArgumentNullException.ThrowIfNull(header);

        _logger.LogDebug("Attempting to validate signature ...");

        var jwk = header.Jwk;
        if (jwk == null)
        {
            try
            {
                var accountId = header.GetAccountId();
                var account = await _accountService.LoadAccount(accountId, cancellationToken).ConfigureAwait(false);
                if (account == null)
                {
                    throw new AccountDoesNotExistException();
                }

                jwk = account.Jwk;
            }
            catch (InvalidOperationException)
            {
                throw new MalformedRequestException("KID could not be found.");
            }
        }

        if (jwk == null)
        {
            throw new MalformedRequestException("Could not load JWK.");
        }

        using var signatureProvider = new AsymmetricSignatureProvider(jwk, header.Alg);
        var plainText = System.Text.Encoding.UTF8.GetBytes($"{request.Protected}.{request.Payload ?? ""}");
        var signature = Base64UrlEncoder.DecodeBytes(request.Signature);

        if (!signatureProvider.Verify(plainText, signature))
        {
            throw new MalformedRequestException("The signature could not be verified");
        }

        _logger.LogDebug("successfully validated signature");
    }
}
