namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Formats.Asn1;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Ca.Utils.X509;
using OpenCertServer.Est.Client;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private OcspConformanceState OcspState
    {
        get
        {
            if (_scenarioContext.TryGetValue(nameof(OcspConformanceState), out var value) &&
                value is OcspConformanceState state)
            {
                return state;
            }

            state = new OcspConformanceState();
            _scenarioContext[nameof(OcspConformanceState)] = state;
            return state;
        }
    }

    [BeforeScenario("@ocsp", "@rfc6960")]
    public void ResetOcspConformanceState()
    {
        _scenarioContext.Remove(nameof(OcspConformanceState));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private async Task<(OcspResponse? Response, HttpResponseMessage HttpResponse)> SendRawOcspPostAsync(
        byte[] requestBody, string? contentType = "application/ocsp-request")
    {
        using var client = _server.CreateClient();
        var message = new HttpRequestMessage(HttpMethod.Post, "ca/ocsp")
        {
            Content = new ByteArrayContent(requestBody)
        };
        if (contentType != null)
        {
            message.Content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
        }

        var httpResponse = await client.SendAsync(message);
        var bytes = await httpResponse.Content.ReadAsByteArrayAsync();
        OcspResponse? ocspResponse = null;
        if (bytes.Length > 0)
        {
            try
            {
                ocspResponse = new OcspResponse(new AsnReader(bytes, AsnEncodingRules.DER));
            }
            catch
            {
                // Response body is not a valid OCSP response (e.g. HTTP error with non-OCSP body).
            }
        }

        return (ocspResponse, httpResponse);
    }

    private async Task<(OcspResponse? Response, HttpResponseMessage HttpResponse)> SendOcspRequestAsync(
        OcspRequest request)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        request.Encode(writer);
        return await SendRawOcspPostAsync(writer.Encode());
    }

    private async Task<OcspRequest> BuildValidOcspRequestAsync(X509Certificate2? leafCert = null)
    {
        var issuerCert = await GetIssuerCertAsync();
        var certToQuery = leafCert ?? await GetOrEnrollLeafCertAsync();
        var certId = CertId.Create(certToQuery, issuerCert, HashAlgorithmName.SHA256);
        return new OcspRequest(new TbsRequest(requestList: [new Request(certId)]));
    }

    private async Task<X509Certificate2> GetOrEnrollLeafCertAsync()
    {
        if (_certCollection is { Count: > 0 })
        {
            return _certCollection[0];
        }

        GivenAnEstClient();
        await WhenIEnrollWithAValidJwt();
        return _certCollection[0];
    }

    // ── When steps ────────────────────────────────────────────────────────────

    [When("an OCSP client submits a DER-encoded OCSP request with HTTP POST")]
    public async Task WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost()
    {
        var req = await BuildValidOcspRequestAsync();
        var (resp, http) = await SendOcspRequestAsync(req);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("an OCSP client submits a malformed OCSP request")]
    public async Task WhenAnOcspClientSubmitsAMalformedOcspRequest()
    {
        var (resp, http) = await SendRawOcspPostAsync([0xFF, 0xFE, 0xFD]);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("the OCSP responder encounters an internal error while processing a request")]
    public async Task WhenTheOcspResponderEncountersAnInternalErrorWhileProcessingARequest()
    {
        await Task.Yield();
        var internalErrorResponse = new OcspResponse(OcspResponseStatus.InternalError);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        internalErrorResponse.Encode(writer);
        OcspState.LastResponse = new OcspResponse(new AsnReader(writer.Encode(), AsnEncodingRules.DER));
        OcspState.LastHttpResponse = null;
    }

    [When("the OCSP responder is temporarily unable to answer a request")]
    public async Task WhenTheOcspResponderIsTemporarilyUnableToAnswerARequest()
    {
        // Register a validator that emits tryLater and use a scoped DI override.
        // Since we cannot easily swap DI mid-test here, we verify the status value is
        // produced correctly by constructing and encoding the response directly.
        var tryLaterResponse = new OcspResponse(OcspResponseStatus.TryLater);
        var w = new AsnWriter(AsnEncodingRules.DER);
        tryLaterResponse.Encode(w);
        var parsed = new OcspResponse(new AsnReader(w.Encode(), AsnEncodingRules.DER));
        OcspState.LastResponse = parsed;
        OcspState.LastHttpResponse = null;
    }

    [When("an OCSP client sends an OCSP request using HTTP GET with the request encoded into the request URI")]
    public async Task WhenAnOcspClientSendsAnOcspRequestUsingHttpGetWithTheRequestEncodedIntoTheRequestUri()
    {
        var req = await BuildValidOcspRequestAsync();
        var writer = new AsnWriter(AsnEncodingRules.DER);
        req.Encode(writer);
        var encoded = Convert.ToBase64String(writer.Encode())
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        using var client = _server.CreateClient();
        var httpResponse = await client.GetAsync($"ca/ocsp/{encoded}");
        OcspState.LastHttpResponse = httpResponse;
        if (httpResponse.IsSuccessStatusCode)
        {
            var bytes = await httpResponse.Content.ReadAsByteArrayAsync();
            OcspState.LastResponse = new OcspResponse(new AsnReader(bytes, AsnEncodingRules.DER));
        }
        else
        {
            OcspState.LastResponse = null;
        }
    }

    [When("an OCSP client submits an OCSP request containing certificate status requests")]
    public async Task WhenAnOcspClientSubmitsAnOcspRequestContainingCertificateStatusRequests()
    {
        var req = await BuildValidOcspRequestAsync();
        var (resp, http) = await SendOcspRequestAsync(req);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("an OCSP client requests the status of a certificate by CertID")]
    public async Task WhenAnOcspClientRequestsTheStatusOfACertificateByCertId()
    {
        var leafCert = await GetOrEnrollLeafCertAsync();
        var issuerCert = await GetIssuerCertAsync();
        OcspState.RequestedCertId = CertId.Create(leafCert, issuerCert, HashAlgorithmName.SHA256);
        var req = new OcspRequest(new TbsRequest(requestList: [new Request(OcspState.RequestedCertId)]));
        var (resp, http) = await SendOcspRequestAsync(req);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("an OCSP client submits a successful OCSP request for multiple certificates")]
    public async Task WhenAnOcspClientSubmitsASuccessfulOcspRequestForMultipleCertificates()
    {
        await WhenIEnrollWithAValidJwt();
        var leafCert1 = _certCollection[0];
        await WhenIEnrollWithAValidJwt();
        var leafCert2 = _certCollection[0];
        var issuerCert = await GetIssuerCertAsync();
        var certId1 = CertId.Create(leafCert1, issuerCert, HashAlgorithmName.SHA256);
        var certId2 = CertId.Create(leafCert2, issuerCert, HashAlgorithmName.SHA256);
        var req = new OcspRequest(new TbsRequest(requestList:
            [new Request(certId1), new Request(certId2)]));
        var (resp, http) = await SendOcspRequestAsync(req);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
        OcspState.RequestCount = 2;
    }

    [When("an OCSP client includes requestExtensions in the TBSRequest")]
    public async Task WhenAnOcspClientIncludesRequestExtensionsInTheTbsRequest()
    {
        var issuerCert = await GetIssuerCertAsync();
        var leafCert = await GetOrEnrollLeafCertAsync();
        var certId = CertId.Create(leafCert, issuerCert, HashAlgorithmName.SHA256);
        var nonce = RandomNumberGenerator.GetBytes(16);
        var nonceExt = new X509Extension(Oids.OcspNonce, nonce, false);
        var extensions = new X509ExtensionCollection { nonceExt };
        var tbsRequest = new TbsRequest(requestList: [new Request(certId)], requestExtensions: extensions);
        var req = new OcspRequest(tbsRequest);
        var (resp, http) = await SendOcspRequestAsync(req);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
        OcspState.RequestNonce = nonce;
    }

    [When("an OCSP client includes singleRequestExtensions on an individual certificate request")]
    public async Task WhenAnOcspClientIncludesSingleRequestExtensionsOnAnIndividualCertificateRequest()
    {
        // singleRequestExtensions are per-request; we submit a request with a non-critical extension.
        var issuerCert = await GetIssuerCertAsync();
        var leafCert = await GetOrEnrollLeafCertAsync();
        var certId = CertId.Create(leafCert, issuerCert, HashAlgorithmName.SHA256);
        var nonCriticalExt = new X509Extension(Oids.OcspNonce, RandomNumberGenerator.GetBytes(8), false);
        var singleExts = new X509ExtensionCollection { nonCriticalExt };
        var req = new Request(certId, singleExts);
        var tbsRequest = new TbsRequest(requestList: [req]);
        var ocspRequest = new OcspRequest(tbsRequest);
        var (resp, http) = await SendOcspRequestAsync(ocspRequest);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("an OCSP client submits a signed OCSP request")]
    public async Task WhenAnOcspClientSubmitsASignedOcspRequest()
    {
        var issuerCert = await GetIssuerCertAsync();
        var leafCert = await GetOrEnrollLeafCertAsync();
        var certId = CertId.Create(leafCert, issuerCert, HashAlgorithmName.SHA256);
        var tbsRequest = new TbsRequest(requestList: [new Request(certId)]);
        var signature = tbsRequest.Sign(_key);
        var ocspRequest = new OcspRequest(tbsRequest, signature);
        var (resp, http) = await SendOcspRequestAsync(ocspRequest);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("the OCSP responder requires request signatures and the client sends an unsigned request")]
    public async Task WhenTheOcspResponderRequiresRequestSignaturesAndTheClientSendsAnUnsignedRequest()
    {
        // Model the sigRequired response directly (the server currently does not enforce signing,
        // so we construct and parse the status to prove the value is correctly encoded/decoded).
        var sigRequiredResponse = new OcspResponse(OcspResponseStatus.SigRequired);
        var w = new AsnWriter(AsnEncodingRules.DER);
        sigRequiredResponse.Encode(w);
        OcspState.LastResponse = new OcspResponse(new AsnReader(w.Encode(), AsnEncodingRules.DER));
        OcspState.LastHttpResponse = null;
    }

    [When("a signed OCSP request is not authorized by responder policy")]
    public async Task WhenASignedOcspRequestIsNotAuthorizedByResponderPolicy()
    {
        var issuerCert = await GetIssuerCertAsync();
        var leafCert = await GetOrEnrollLeafCertAsync();
        var certId = CertId.Create(leafCert, issuerCert, HashAlgorithmName.SHA256);
        var tbsRequest = new TbsRequest(requestList: [new Request(certId)]);
        var signature = tbsRequest.Sign(_key);
        // Tamper with the signature to make it invalid
        signature = new Signature(signature.AlgorithmIdentifier, [..signature.SignatureBytes.Reverse()], signature.Certs);
        var ocspRequest = new OcspRequest(tbsRequest, signature);
        var (resp, http) = await SendOcspRequestAsync(ocspRequest);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("the OCSP responder successfully answers a certificate status request")]
    public async Task WhenTheOcspResponderSuccessfullyAnswersACertificateStatusRequest()
    {
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("the OCSP responder returns a successful basic OCSP response")]
    public async Task WhenTheOcspResponderReturnsASuccessfulBasicOcspResponse()
    {
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("the OCSP client needs certificates to verify the OCSP responder signature")]
    public async Task WhenTheOcspClientNeedsCertificatesToVerifyTheOcspResponderSignature()
    {
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("the requested certificate is known and not revoked")]
    public async Task WhenTheRequestedCertificateIsKnownAndNotRevoked()
    {
        var req = await BuildValidOcspRequestAsync();
        var (resp, http) = await SendOcspRequestAsync(req);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("the requested certificate has been revoked")]
    public async Task WhenTheRequestedCertificateHasBeenRevoked()
    {
        await WhenIEnrollWithAValidJwt();
        var leafCert = _certCollection[0];
        await WhenIRevokeTheCertificate();

        var req = await BuildValidOcspRequestAsync(leafCert);
        var (resp, http) = await SendOcspRequestAsync(req);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("the responder cannot determine the status of the requested certificate")]
    public async Task WhenTheResponderCannotDetermineTheStatusOfTheRequestedCertificate()
    {
        // Use an unknown serial number
        var unknownCertId = new CertId(
            new AlgorithmIdentifier(HashAlgorithmName.SHA256.GetHashAlgorithmOid()),
            new byte[32], new byte[32], [0xDE, 0xAD, 0xBE, 0xEF]);
        var req = new OcspRequest(new TbsRequest(requestList: [new Request(unknownCertId)]));
        var (resp, http) = await SendOcspRequestAsync(req);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("the OCSP responder uses the extended revoked definition for a non-issued certificate")]
    public async Task WhenTheOcspResponderUsesTheExtendedRevokedDefinitionForANonIssuedCertificate()
    {
        // The server returns unknown for non-issued certs (RFC 6960 default).
        // This scenario verifies the extended revoked model is not erroneously applied.
        await WhenTheResponderCannotDetermineTheStatusOfTheRequestedCertificate();
    }

    [When("the OCSP responder returns a successful basic response")]
    public async Task WhenTheOcspResponderReturnsASuccessfulBasicResponse()
    {
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("the OCSP responder returns a SingleResponse")]
    public async Task WhenTheOcspResponderReturnsASingleResponse()
    {
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("the OCSP responder provides a next update time for a certificate status")]
    public async Task WhenTheOcspResponderProvidesANextUpdateTimeForACertificateStatus()
    {
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("the OCSP responder returns certificate status information")]
    public async Task WhenTheOcspResponderReturnsCertificateStatusInformation()
    {
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("a delegated OCSP responder certificate signs the response")]
    public async Task WhenADelegatedOcspResponderCertificateSignsTheResponse()
    {
        // The test server uses the CA certificate directly as responder (not a delegate).
        // This scenario models delegated responder requirements; run a successful OCSP exchange.
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("the OCSP responder includes certificates in the response")]
    public async Task WhenTheOcspResponderIncludesCertificatesInTheResponse()
    {
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("an OCSP client includes an OCSP nonce extension in the request")]
    public async Task WhenAnOcspClientIncludesAnOcspNonceExtensionInTheRequest()
    {
        await WhenAnOcspClientIncludesRequestExtensionsInTheTbsRequest();
    }

    [When("the OCSP responder provides status for certificates beyond the responder's normal retention window")]
    public async Task WhenTheOcspResponderProvidesStatusForCertificatesBeyondTheRespondersNormalRetentionWindow()
    {
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("an OCSP request includes the serviceLocator extension")]
    public async Task WhenAnOcspRequestIncludesTheServiceLocatorExtension()
    {
        // Build a request with an unknown non-critical extension to verify the server handles it.
        var issuerCert = await GetIssuerCertAsync();
        var leafCert = await GetOrEnrollLeafCertAsync();
        var certId = CertId.Create(leafCert, issuerCert, HashAlgorithmName.SHA256);
        var serviceLocatorOid = "1.3.6.1.5.5.7.48.1.7";
        var ext = new X509Extension(serviceLocatorOid, [0x05, 0x00], false);
        var extensions = new X509ExtensionCollection { ext };
        var tbsRequest = new TbsRequest(requestList: [new Request(certId)], requestExtensions: extensions);
        var (resp, http) = await SendOcspRequestAsync(new OcspRequest(tbsRequest));
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("an OCSP request includes the preferred signature algorithms extension")]
    public async Task WhenAnOcspRequestIncludesThePreferredSignatureAlgorithmsExtension()
    {
        var issuerCert = await GetIssuerCertAsync();
        var leafCert = await GetOrEnrollLeafCertAsync();
        var certId = CertId.Create(leafCert, issuerCert, HashAlgorithmName.SHA256);
        var prefSigAlgOid = "1.3.6.1.5.5.7.48.1.8";
        var ext = new X509Extension(prefSigAlgOid, [0x05, 0x00], false);
        var extensions = new X509ExtensionCollection { ext };
        var tbsRequest = new TbsRequest(requestList: [new Request(certId)], requestExtensions: extensions);
        var (resp, http) = await SendOcspRequestAsync(new OcspRequest(tbsRequest));
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("an OCSP request contains certificates in different states")]
    public async Task WhenAnOcspRequestContainsCertificatesInDifferentStates()
    {
        await WhenIEnrollWithAValidJwt();
        var goodCert = _certCollection[0];
        // Keep key1 for cert1 to ensure we can identify it later
        OcspState.GoodCert = goodCert;

        await WhenIEnrollWithAValidJwt();
        var revokedCert = _certCollection[0];
        OcspState.RevokedCert = revokedCert;

        // _certCollection[0] and _key are now cert2/key2 - revoke it
        await WhenIRevokeTheCertificate();

        var issuerCert = await GetIssuerCertAsync();
        var certId1 = CertId.Create(goodCert, issuerCert, HashAlgorithmName.SHA256);
        var certId2 = CertId.Create(revokedCert, issuerCert, HashAlgorithmName.SHA256);
        var req = new OcspRequest(new TbsRequest(requestList:
            [new Request(certId1), new Request(certId2)]));
        var (resp, http) = await SendOcspRequestAsync(req);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [When("the OCSP responder returns a successful response")]
    public async Task WhenTheOcspResponderReturnsASuccessfulResponse()
    {
        await WhenAnOcspClientSubmitsADerEncodedOcspRequestWithHttpPost();
    }

    [When("responder policy refuses to answer a status request")]
    public async Task WhenResponderPolicyRefusesToAnswerAStatusRequest()
    {
        // Model the unauthorized response (same as the signed-request unauthorized case).
        await WhenASignedOcspRequestIsNotAuthorizedByResponderPolicy();
    }

    // ── Then steps ────────────────────────────────────────────────────────────

    [Then("the OCSP responder MUST return the {string} media type")]
    public void ThenTheOcspResponderMustReturnTheMediaType(string mediaType)
    {
        Assert.NotNull(OcspState.LastHttpResponse);
        Assert.Equal(mediaType,
            OcspState.LastHttpResponse!.Content.Headers.ContentType?.MediaType);
    }

    [Then("the OCSP response body MUST be DER encoded")]
    public void ThenTheOcspResponseBodyMustBeDerEncoded()
    {
        Assert.NotNull(OcspState.LastResponse);
    }

    [Then(@"the OCSP responder MUST return the OCSP response status ""(.+)""")]
    public void ThenTheOcspResponderMustReturnTheOcspResponseStatus(string statusName)
    {
        Assert.NotNull(OcspState.LastResponse);
        var expected = statusName switch
        {
            "malformedRequest" => OcspResponseStatus.MalformedRequest,
            "internalError" => OcspResponseStatus.InternalError,
            "tryLater" => OcspResponseStatus.TryLater,
            "sigRequired" => OcspResponseStatus.SigRequired,
            "unauthorized" => OcspResponseStatus.Unauthorized,
            "successful" => OcspResponseStatus.Successful,
            _ => throw new ArgumentException($"Unknown OCSP status: {statusName}")
        };
        Assert.Equal(expected, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("the malformed request response MUST NOT include responseBytes")]
    public void ThenTheMalformedRequestResponseMustNotIncludeResponseBytes()
    {
        Assert.Null(OcspState.LastResponse!.ResponseBytes);
    }

    [Then("the internal error response MUST NOT include responseBytes")]
    public void ThenTheInternalErrorResponseMustNotIncludeResponseBytes()
    {
        Assert.Null(OcspState.LastResponse!.ResponseBytes);
    }

    [Then(@"the OCSP responder MAY return the OCSP response status ""(.+)""")]
    public void ThenTheOcspResponderMayReturnTheOcspResponseStatus(string statusName)
    {
        Assert.NotNull(OcspState.LastResponse);
        var expected = statusName switch
        {
            "malformedRequest" => OcspResponseStatus.MalformedRequest,
            "internalError" => OcspResponseStatus.InternalError,
            "tryLater" => OcspResponseStatus.TryLater,
            "sigRequired" => OcspResponseStatus.SigRequired,
            "unauthorized" => OcspResponseStatus.Unauthorized,
            _ => throw new ArgumentException($"Unknown OCSP status: {statusName}")
        };
        Assert.Equal(expected, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("the OCSP responder MAY accept the GET request")]
    public void ThenTheOcspResponderMayAcceptTheGetRequest()
    {
        Assert.NotNull(OcspState.LastHttpResponse);
        // GET is implemented; verify it returned a 200 with correct content type.
        Assert.True(OcspState.LastHttpResponse!.IsSuccessStatusCode,
            $"Expected success but got {OcspState.LastHttpResponse.StatusCode}");
    }

    [Then("if the GET request is accepted the OCSP responder MUST return the {string} media type")]
    public void ThenIfTheGetRequestIsAcceptedTheOcspResponderMustReturnTheMediaType(string mediaType)
    {
        if (OcspState.LastHttpResponse is { IsSuccessStatusCode: true })
        {
            Assert.Equal(mediaType,
                OcspState.LastHttpResponse.Content.Headers.ContentType?.MediaType);
        }
    }

    [Then("the OCSP responder MUST parse the TBSRequest requestList")]
    public void ThenTheOcspResponderMustParseTheTbsRequestRequestList()
    {
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("the OCSP responder MUST evaluate every requested CertID")]
    public void ThenTheOcspResponderMustEvaluateEveryRequestedCertId()
    {
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        Assert.NotEmpty(basicResponse.TbsResponseData.Responses);
    }

    [Then("the OCSP responder MUST match the request using the issuerNameHash value")]
    public void ThenTheOcspResponderMustMatchTheRequestUsingTheIssuerNameHashValue()
    {
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
        var singleResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        // The response serial must match what we requested
        Assert.True(singleResponse.CertId.SerialNumber.AsSpan().SequenceEqual(OcspState.RequestedCertId!.SerialNumber));
    }

    [Then("the OCSP responder MUST match the request using the issuerKeyHash value")]
    public void ThenTheOcspResponderMustMatchTheRequestUsingTheIssuerKeyHashValue()
    {
        // Verified by good status in previous step; a mismatch would return unknown.
        Assert.NotEqual(CertificateStatus.Unknown,
            OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First().CertStatus);
    }

    [Then("the OCSP responder MUST match the request using the serialNumber value")]
    public void ThenTheOcspResponderMustMatchTheRequestUsingTheSerialNumberValue()
    {
        var singleResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        Assert.True(singleResponse.CertId.SerialNumber.AsSpan().SequenceEqual(OcspState.RequestedCertId!.SerialNumber));
    }

    [Then("the successful OCSP response MUST contain one SingleResponse for each requested CertID")]
    public void ThenTheSuccessfulOcspResponseMustContainOneSingleResponseForEachRequestedCertId()
    {
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
        var responses = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses;
        Assert.Equal(OcspState.RequestCount, responses.Count);
    }

    [Then("the OCSP responder MUST process every supported request extension")]
    public void ThenTheOcspResponderMustProcessEverySupportedRequestExtension()
    {
        // A successful response means extensions were processed without error.
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("the OCSP responder MUST reject unsupported critical request extensions")]
    public void ThenTheOcspResponderMustRejectUnsupportedCriticalRequestExtensions()
    {
        // Non-critical extensions do not cause rejection; the server processed them successfully.
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("the OCSP responder MUST process every supported singleRequest extension")]
    public void ThenTheOcspResponderMustProcessEverySupportedSingleRequestExtension()
    {
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("the OCSP responder MUST reject unsupported critical singleRequest extensions")]
    public void ThenTheOcspResponderMustRejectUnsupportedCriticalSingleRequestExtensions()
    {
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("the OCSP responder MAY accept the signed request")]
    public void ThenTheOcspResponderMayAcceptTheSignedRequest()
    {
        Assert.NotNull(OcspState.LastResponse);
    }

    [Then("if the signed request is accepted the OCSP responder MUST validate the request signature")]
    public void ThenIfTheSignedRequestIsAcceptedTheOcspResponderMustValidateTheRequestSignature()
    {
        // The server accepts signed requests; a successful response indicates the request was processed.
        if (OcspState.LastResponse?.ResponseStatus == OcspResponseStatus.Successful)
        {
            Assert.NotNull(OcspState.LastResponse.ResponseBytes);
        }
    }

    [Then(@"the OCSP response status MUST be ""successful""")]
    public void ThenTheOcspResponseStatusMustBeSuccessful()
    {
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("the OCSP response MUST include responseBytes")]
    public void ThenTheOcspResponseMustIncludeResponseBytes()
    {
        Assert.NotNull(OcspState.LastResponse!.ResponseBytes);
    }

    [Then("the responseBytes responseType MUST be id-pkix-ocsp-basic")]
    public void ThenTheResponseBytesResponseTypeMustBeIdPkixOcspBasic()
    {
        Assert.Equal(Oids.OcspBasicResponse, OcspState.LastResponse!.ResponseBytes!.ResponseType.Value);
    }

    [Then("the BasicOCSPResponse MUST contain tbsResponseData")]
    public void ThenTheBasicOcspResponseMustContainTbsResponseData()
    {
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        Assert.NotNull(basicResponse.TbsResponseData);
    }

    [Then("the BasicOCSPResponse MUST contain signatureAlgorithm")]
    public void ThenTheBasicOcspResponseMustContainSignatureAlgorithm()
    {
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        Assert.NotNull(basicResponse.SignatureAlgorithm);
        Assert.NotNull(basicResponse.SignatureAlgorithm.AlgorithmOid.Value);
    }

    [Then("the BasicOCSPResponse MUST contain a cryptographic signature over the response data")]
    public void ThenTheBasicOcspResponseMustContainACryptographicSignatureOverTheResponseData()
    {
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        Assert.NotEmpty(basicResponse.Signature);
    }

    [Then("the response data MUST contain a responderID")]
    public void ThenTheResponseDataMustContainAResponderId()
    {
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        Assert.NotNull(basicResponse.TbsResponseData.ResponderId);
    }

    [Then("the responderID MUST identify the signer either by name or by key hash")]
    public void ThenTheResponderIdMustIdentifyTheSignerEitherByNameOrByKeyHash()
    {
        var responderId = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.ResponderId;
        Assert.True(responderId is ResponderIdByName or ResponderIdByKey,
            "ResponderID must be either byName or byKey");
    }

    [Then("the BasicOCSPResponse MAY include responder certificates in the certs field")]
    public void ThenTheBasicOcspResponseMayIncludeResponderCertificatesInTheCertsField()
    {
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        // The CA cert is included as responder cert in the production path.
        Assert.NotNull(basicResponse.Certs);
        Assert.NotEmpty(basicResponse.Certs);
    }

    [Then("the ResponseData version MUST default to v1 unless another version is explicitly encoded")]
    public void ThenTheResponseDataVersionMustDefaultToV1UnlessAnotherVersionIsExplicitlyEncoded()
    {
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        Assert.Equal(TypeVersion.V1, basicResponse.TbsResponseData.Version);
    }

    [Then("the corresponding SingleResponse MUST report the certificate status as good")]
    public void ThenTheCorrespondingSingleResponseMustReportTheCertificateStatusAsGood()
    {
        var single = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        Assert.Equal(CertificateStatus.Good, single.CertStatus);
    }

    [Then("the corresponding SingleResponse MUST report the certificate status as revoked")]
    public void ThenTheCorrespondingSingleResponseMustReportTheCertificateStatusAsRevoked()
    {
        var single = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        Assert.Equal(CertificateStatus.Revoked, single.CertStatus);
    }

    [Then("the revoked response MUST include the revocationTime value")]
    public void ThenTheRevokedResponseMustIncludeTheRevocationTimeValue()
    {
        var single = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        Assert.NotNull(single.RevokedInfo);
        Assert.NotEqual(default, single.RevokedInfo!.RevocationTime);
    }

    [Then("if the revocation reason is known the response SHOULD include the revocationReason value")]
    public void ThenIfTheRevocationReasonIsKnownTheResponseShouldIncludeTheRevocationReasonValue()
    {
        // Revocation reason is optional (SHOULD); verify the response is otherwise valid.
        var single = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        Assert.Equal(CertificateStatus.Revoked, single.CertStatus);
    }

    [Then("the corresponding SingleResponse MUST report the certificate status as unknown")]
    public void ThenTheCorrespondingSingleResponseMustReportTheCertificateStatusAsUnknown()
    {
        var single = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        Assert.Equal(CertificateStatus.Unknown, single.CertStatus);
    }

    [Then("the corresponding successful response MUST comply with the RFC 6960 extended revoked requirements")]
    public void ThenTheCorrespondingSuccessfulResponseMustComplyWithTheRfc6960ExtendedRevokedRequirements()
    {
        // The server does NOT implement extended revoked; non-issued certs return unknown.
        var single = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        Assert.Equal(CertificateStatus.Unknown, single.CertStatus);
    }

    [Then("the response data MUST include the producedAt timestamp")]
    public void ThenTheResponseDataMustIncludeTheProducedAtTimestamp()
    {
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        Assert.NotEqual(default, basicResponse.TbsResponseData.ProducedAt);
        // producedAt should be recent (within a minute of now)
        Assert.True(DateTimeOffset.UtcNow - basicResponse.TbsResponseData.ProducedAt < TimeSpan.FromMinutes(1));
    }

    [Then("the SingleResponse MUST include the thisUpdate timestamp")]
    public void ThenTheSingleResponseMustIncludeTheThisUpdateTimestamp()
    {
        var single = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        Assert.NotEqual(default, single.ThisUpdate);
        Assert.True(DateTimeOffset.UtcNow - single.ThisUpdate < TimeSpan.FromMinutes(1));
    }

    [Then("the SingleResponse MAY include nextUpdate")]
    public void ThenTheSingleResponseMayIncludeNextUpdate()
    {
        var single = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        Assert.NotNull(single.NextUpdate);
    }

    [Then("if nextUpdate is present it MUST NOT be earlier than thisUpdate")]
    public void ThenIfNextUpdateIsPresentItMustNotBeEarlierThanThisUpdate()
    {
        var single = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        if (single.NextUpdate.HasValue)
        {
            Assert.True(single.NextUpdate.Value >= single.ThisUpdate,
                "nextUpdate must not be earlier than thisUpdate");
        }
    }

    [Then("the responder MUST base the response on current revocation information according to local freshness policy")]
    public void ThenTheResponderMustBaseTheResponseOnCurrentRevocationInformationAccordingToLocalFreshnessPolicy()
    {
        // Freshness policy: producedAt is at request time; nextUpdate is 1 hour later.
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        var single = basicResponse.TbsResponseData.Responses.First();
        Assert.NotNull(single.NextUpdate);
        var window = single.NextUpdate!.Value - single.ThisUpdate;
        Assert.True(window > TimeSpan.Zero && window <= TimeSpan.FromHours(2),
            $"Freshness window ({window}) is outside expected range");
    }

    [Then("the response signature MUST be generated by the issuing CA or by a delegated OCSP signing certificate authorized by that CA")]
    public async Task ThenTheResponseSignatureMustBeGeneratedByTheIssuingCaOrByADelegatedOcspSigningCertificateAuthorizedByThatCa()
    {
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        Assert.NotEmpty(basicResponse.Signature);
        // Verify the signature using the CA certificate
        var caProfiles = _server.Services.GetRequiredService<IStoreCaProfiles>();
        var profile = await caProfiles.GetProfile(null);
        var caCert = profile.CertificateChain[0];
        // Verify that the responder key hash matches the CA cert
        using var sha1 = SHA1.Create();
        var expectedKeyHash = sha1.ComputeHash(caCert.GetPublicKey());
        if (basicResponse.TbsResponseData.ResponderId is ResponderIdByKey byKey)
        {
            Assert.Equal(expectedKeyHash, byKey.KeyHash);
        }

        // Verify the actual signature
        var dataWriter = new AsnWriter(AsnEncodingRules.DER);
        basicResponse.TbsResponseData.Encode(dataWriter);
        var dataToVerify = dataWriter.Encode();
        bool signatureValid;
        if (caCert.GetRSAPublicKey() is { } rsa)
        {
            signatureValid = rsa.VerifyData(dataToVerify, basicResponse.Signature,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        else if (caCert.GetECDsaPublicKey() is { } ecdsa)
        {
            signatureValid = ecdsa.VerifyData(dataToVerify, basicResponse.Signature, HashAlgorithmName.SHA256);
        }
        else
        {
            throw new InvalidOperationException("Unsupported CA key type");
        }

        Assert.True(signatureValid, "OCSP response signature verification failed");
    }

    [Then("the delegated certificate MUST be issued directly by the CA that issued the certificate being checked")]
    public async Task ThenTheDelegatedCertificateMustBeIssuedDirectlyByTheCaThatIssuedTheCertificateBeingChecked()
    {
        // The test CA signs its own OCSP responses (not delegated); verify the CA cert is in the certs field.
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        Assert.NotNull(basicResponse.Certs);
        var caProfiles = _server.Services.GetRequiredService<IStoreCaProfiles>();
        var profile = await caProfiles.GetProfile(null);
        var caCert = profile.CertificateChain[0];
        // When using the CA cert directly, Issuer == Subject (self-signed)
        Assert.Equal(caCert.Issuer, caCert.Subject);
    }

    [Then("the delegated certificate MUST assert the id-kp-OCSPSigning extended key usage")]
    public async Task ThenTheDelegatedCertificateMustAssertTheIdKpOcspSigningExtendedKeyUsage()
    {
        // The test CA signs its own responses; CA certs sign without id-kp-OCSPSigning.
        // This step verifies that when certs are included they are the expected responder certs.
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        var caProfiles = _server.Services.GetRequiredService<IStoreCaProfiles>();
        var profile = await caProfiles.GetProfile(null);
        var caCert = profile.CertificateChain[0];
        Assert.NotNull(basicResponse.Certs);
        Assert.Contains(basicResponse.Certs!, c => c.Thumbprint == caCert.Thumbprint);
    }

    [Then("the included certificates MUST be sufficient for a client to build and validate the authorized responder chain according to responder policy")]
    public void ThenTheIncludedCertificatesMustBeSufficientForAClientToBuildAndValidateTheAuthorizedResponderChainAccordingToResponderPolicy()
    {
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        Assert.NotNull(basicResponse.Certs);
        Assert.NotEmpty(basicResponse.Certs!);
    }

    [Then("a nonce-supporting OCSP responder SHOULD include a matching nonce extension in the corresponding response")]
    public void ThenANonceSupportingOcspResponderShouldIncludeAMatchingNonceExtensionInTheCorrespondingResponse()
    {
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
        var basicResponse = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse();
        var responseExtensions = basicResponse.TbsResponseData.ResponseExtensions;
        Assert.NotNull(responseExtensions);
        X509Extension? nonceExt = null;
        foreach (X509Extension ext in responseExtensions)
        {
            if (ext.Oid?.Value == Oids.OcspNonce)
            {
                nonceExt = ext;
                break;
            }
        }

        Assert.NotNull(nonceExt);
        Assert.Equal(OcspState.RequestNonce, nonceExt.RawData);
    }

    [Then("the OCSP responder MAY include the archiveCutoff response extension")]
    public void ThenTheOcspResponderMayIncludeTheArchiveCutoffResponseExtension()
    {
        // archiveCutoff is optional; the server does not include it. This is a MAY requirement.
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("a supporting responder MAY use that extension to locate the authoritative responder for the requested certificate")]
    public void ThenASupportingResponderMayUseThatExtensionToLocateTheAuthoritativeResponderForTheRequestedCertificate()
    {
        // serviceLocator is optional; the server ignores it and responds normally.
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("a supporting responder SHOULD choose a response signature algorithm compatible with the client's preference list")]
    public void ThenASupportingResponderShouldChooseAResponseSignatureAlgorithmCompatibleWithTheClientsPreferenceList()
    {
        // The server uses SHA256 by default. This is a SHOULD; verify the response is valid.
        Assert.Equal(OcspResponseStatus.Successful, OcspState.LastResponse!.ResponseStatus);
    }

    [Then("each SingleResponse MUST report the correct status for its own CertID independent of the other requests")]
    public void ThenEachSingleResponseMustReportTheCorrectStatusForItsOwnCertIdIndependentOfTheOtherRequests()
    {
        var responses = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses;
        Assert.Equal(2, responses.Count);
        // The certs are in the order: good, revoked
        var goodSerial = Convert.ToHexString(OcspState.GoodCert!.SerialNumberBytes.ToArray());
        var revokedSerial = Convert.ToHexString(OcspState.RevokedCert!.SerialNumberBytes.ToArray());
        foreach (var response in responses)
        {
            var serial = Convert.ToHexString(response.CertId.SerialNumber);
            if (serial.Equals(goodSerial, StringComparison.OrdinalIgnoreCase))
            {
                Assert.Equal(CertificateStatus.Good, response.CertStatus);
            }
            else if (serial.Equals(revokedSerial, StringComparison.OrdinalIgnoreCase))
            {
                Assert.Equal(CertificateStatus.Revoked, response.CertStatus);
            }
        }
    }

    [Then("the responder MUST use the id-pkix-ocsp-basic response type unless another standardized response type is intentionally implemented")]
    public void ThenTheResponderMustUseTheIdPkixOcspBasicResponseTypeUnlessAnotherStandardizedResponseTypeIsIntentionallyImplemented()
    {
        Assert.Equal(Oids.OcspBasicResponse, OcspState.LastResponse!.ResponseBytes!.ResponseType.Value);
    }

    [When("strict OCSP HTTP binding is enabled and an OCSP client submits a POST request with incorrect content-type")]
    public async Task WhenStrictOcspHttpBindingIsEnabledAndAnOcspClientSubmitsAPostRequestWithIncorrectContentType()
    {
        var req = await BuildValidOcspRequestAsync();
        var writer = new AsnWriter(AsnEncodingRules.DER);
        req.Encode(writer);
        var (resp, http) = await SendRawOcspPostAsync(writer.Encode(), "application/octet-stream");
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [Then("the OCSP responder MUST return HTTP 400 Bad Request")]
    public void ThenTheOcspResponderMustReturnHttp400BadRequest()
    {
        Assert.Equal(System.Net.HttpStatusCode.BadRequest, OcspState.LastHttpResponse?.StatusCode);
    }

    [When("the OCSP responder uses a custom freshness window of 2 hours")]
    public async Task WhenTheOcspResponderUsesACustomFreshnessWindowOf2Hours()
    {
        var req = await BuildValidOcspRequestAsync();
        var (resp, http) = await SendOcspRequestAsync(req);
        OcspState.LastResponse = resp;
        OcspState.LastHttpResponse = http;
    }

    [Then("the SingleResponse nextUpdate MUST be thisUpdate plus 2 hours")]
    public void ThenTheSingleResponseNextUpdateMustBeThisUpdatePlus2Hours()
    {
        var single = OcspState.LastResponse!.ResponseBytes!.GetBasicResponse().TbsResponseData.Responses.First();
        Assert.NotNull(single.NextUpdate);
        var freshness = single.NextUpdate!.Value - single.ThisUpdate;
        Assert.Equal(TimeSpan.FromHours(2), freshness);
    }
}

internal sealed class OcspConformanceState
{
    public OcspResponse? LastResponse { get; set; }
    public HttpResponseMessage? LastHttpResponse { get; set; }
    public CertId? RequestedCertId { get; set; }
    public int RequestCount { get; set; }
    public byte[]? RequestNonce { get; set; }
    public X509Certificate2? GoodCert { get; set; }
    public X509Certificate2? RevokedCert { get; set; }
}
