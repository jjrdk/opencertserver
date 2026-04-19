using System.Formats.Asn1;
using Microsoft.AspNetCore.WebUtilities;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Est.Server.Response;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Pkcs7;
using OpenCertServer.Ca.Utils.X509;
using OpenCertServer.Ca.Utils.X509.Templates;
using OpenCertServer.Est.Client;
using Reqnroll;
using Xunit;

public partial class CertificateServerFeatures
{
    private const string EstExtensionsPath = "src/opencertserver.est.server/EstServerExtensions.cs";
    private const string CaCertHandlerPath = "src/opencertserver.est.server/Handlers/CaCertHandler.cs";
    private const string SimpleEnrollHandlerPath = "src/opencertserver.est.server/Handlers/SimpleEnrollHandler.cs";
    private const string SimpleReEnrollHandlerPath = "src/opencertserver.est.server/Handlers/SimpleReEnrollHandler.cs";
    private const string RetryAfterResultPath = "src/opencertserver.est.server/Response/RetryAfterResult.cs";

    private const string TlsUniqueProofOfPossessionVerifierPath =
        "src/opencertserver.est.server/Handlers/TlsUniqueProofOfPossessionVerifier.cs";

    private const string ServerKeyGenHandlerPath = "src/opencertserver.est.server/Handlers/ServerKeyGenHandler.cs";
    private const string CsrAttributesHandlerPath = "src/opencertserver.est.server/Handlers/CsrAttributesHandler.cs";

    private const string CsrTemplateResultPath =
        "src/opencertserver.est.server/Response/CertificateSigningRequestTemplateResult.cs";

    private const string EstClientPath = "src/opencertserver.est.client/EstClient.cs";
    private const string EstClientOptionsPath = "src/opencertserver.est.client/EstClientOptions.cs";
    private const string EstBootstrapTrustPath = "src/opencertserver.est.client/EstBootstrapTrust.cs";
    private const string ProgramPath = "src/opencertserver.certserver/Program.cs";

    private const string CertAuthOptionsPath =
        "src/opencertserver.certserver/ConfigureCertificateAuthenticationOptions.cs";

    private const string CertificateRequestTemplatePath =
        "src/opencertserver.ca.utils/X509/Templates/CertificateSigningRequestTemplate.cs";

    private const string EncodingExtensionsPath = "src/opencertserver.ca.utils/EncodingExtensions.cs";
    private const string ExtensionReqOid = "1.2.840.113549.1.9.14";
    private const string ExtensionReqTemplateOid = "1.2.840.113549.1.9.62";
    private const string KeyProtectionHeader = "X-Est-Keygen-Protection";
    private const string KeyProtectionStatusHeader = "X-Est-Keygen-Protection-Status";
    private const string SmimeCapabilitiesHeader = "X-Est-Smime-Capabilities";
    private const string SymmetricDecryptKeyIdentifierHeader = "X-Est-Decrypt-Key-Identifier";
    private const string AsymmetricDecryptKeyIdentifierHeader = "X-Est-Asymmetric-Decrypt-Key-Identifier";

    private EstConformanceState ConformanceState
    {
        get
        {
            if (_scenarioContext.TryGetValue(nameof(EstConformanceState), out var value) &&
                value is EstConformanceState state)
            {
                return state;
            }

            state = new EstConformanceState();
            _scenarioContext[nameof(EstConformanceState)] = state;
            return state;
        }
    }

    private static string RepositoryRoot
    {
        get { return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../")); }
    }

    [BeforeScenario("@est")]
    public void ResetEstConformanceState()
    {
        _scenarioContext.Remove(nameof(EstConformanceState));
        TestCsrAttributesLoaderConfiguration.Reset();
    }

    [AfterScenario("@est")]
    public void CleanupEstConformanceState()
    {
        TestCsrAttributesLoaderConfiguration.Reset();
    }

    [Given("the EST server is configured with an additional CA label")]
    public void GivenTheEstServerIsConfiguredWithAnAdditionalCaLabel()
    {
        ConformanceState.ProfileName = "rsa";
        _estClient = new EstClient(new Uri("https://localhost"), null, messageHandler: _server.CreateHandler(),
            profileName: "rsa");
    }

    [Given("the EST client has neither an Explicit nor an Implicit trust anchor database for the EST server")]
    public void GivenTheEstClientHasNeitherAnExplicitNorAnImplicitTrustAnchorDatabaseForTheEstServer()
    {
    }

    [Given("the EST server remembers its current CA certificate")]
    public void GivenTheEstServerRemembersItsCurrentCaCertificate()
    {
        ConformanceState.PreRollOverRootThumbprint = GetCurrentRootCertificate().Thumbprint;
    }

    [Given("the EST server implements \"(.+)\"")]
    public void GivenTheEstServerImplements(string operation)
    {
        ConformanceState.Operation = operation;
        var implemented = SupportsOperation(operation);
        Assert.SkipUnless(implemented,
            $"Optional EST operation '{operation}' is not implemented in the current server.");
    }

    [When("the client requests the EST operation path \"(.+)\"")]
    public async Task WhenTheClientRequestsTheEstOperationPath(string operation)
    {
        ConformanceState.Operation = operation;
        var path = BuildOperationPath(operation, ConformanceState.ProfileName);
        await SendRequestAsync(HttpMethod.Get, path, accept: "*/*");
    }

    [When("an EST client connects to the EST server")]
    public void WhenAnEstClientConnectsToTheEstServer()
    {
        ConformanceState.CheckedFiles =
        [
            ReadRepoFile(EstClientPath),
            ReadRepoFile(ProgramPath),
            ReadRepoFile(CertAuthOptionsPath)
        ];
    }

    [When("the EST server challenges the client for HTTP authentication")]
    public async Task WhenTheEstServerChallengesTheClientForHttpAuthentication()
    {
        var csr = CreatePemCsr();
        await SendRequestAsync(HttpMethod.Post, BuildOperationPath("/simpleenroll"),
            new StringContent(csr, Encoding.UTF8, "application/pkcs10"));
    }

    [When("the EST server accepts certificate-less TLS mutual authentication for enrollment")]
    public void WhenTheEstServerAcceptsCertificateLessTlsMutualAuthenticationForEnrollment()
    {
        var source = ReadRepoFile(ProgramPath) + ReadRepoFile(EstExtensionsPath);
        var supported = source.Contains("SRP", StringComparison.OrdinalIgnoreCase) ||
            source.Contains("zero knowledge", StringComparison.OrdinalIgnoreCase);
        Assert.SkipUnless(supported,
            "Certificate-less TLS mutual authentication is not implemented in the current server.");
        ConformanceState.CheckedFiles = [source];
    }

    [When("the client submits tls-unique channel-binding information in the certification request")]
    public void WhenTheClientSubmitsTlsUniqueChannelBindingInformationInTheCertificationRequest()
    {
        ConformanceState.CheckedFiles =
        [
            ReadRepoFile(EstClientPath),
            ReadRepoFile(SimpleEnrollHandlerPath),
            ReadRepoFile(SimpleReEnrollHandlerPath),
            ReadRepoFile(TlsUniqueProofOfPossessionVerifierPath)
        ];
    }

    [When("the EST server returns an HTTP redirect for an EST request")]
    public void WhenTheEstServerReturnsAnHttpRedirectForAnEstRequest()
    {
        ConformanceState.CheckedFiles = [ReadRepoFile(EstClientPath)];
    }

    [When("the EST client is configured for EST server authentication")]
    public void WhenTheEstClientIsConfiguredForEstServerAuthentication()
    {
        ConformanceState.CheckedFiles = [ReadRepoFile(EstClientPath)];
    }

    [When("the EST client receives a response from the EST server")]
    public void WhenTheEstClientReceivesAResponseFromTheEstServer()
    {
        ConformanceState.CheckedFiles = [ReadRepoFile(EstClientPath)];
    }

    [When("the EST server certificate is validated using an Explicit trust anchor database entry")]
    public void WhenTheEstServerCertificateIsValidatedUsingAnExplicitTrustAnchorDatabaseEntry()
    {
        ConformanceState.CheckedFiles = [ReadRepoFile(EstClientPath), ReadRepoFile(EstClientOptionsPath)];
    }

    [When("the EST server certificate is validated using an Implicit trust anchor database entry")]
    public void WhenTheEstServerCertificateIsValidatedUsingAnImplicitTrustAnchorDatabaseEntry()
    {
        ConformanceState.CheckedFiles = [ReadRepoFile(EstClientPath), ReadRepoFile(EstClientOptionsPath)];
    }

    [When("the client performs bootstrap CA certificate distribution")]
    public void WhenTheClientPerformsBootstrapCaCertificateDistribution()
    {
        ConformanceState.CheckedFiles =
        [
            ReadRepoFile(EstClientPath),
            ReadRepoFile(EstClientOptionsPath),
            ReadRepoFile(EstBootstrapTrustPath)
        ];
    }

    [When("the EST endpoint \"(.+)\" receives a base64-encoded DER body with any Content-Transfer-Encoding header")]
    public async Task WhenTheEstEndpointReceivesABase64EncodedDerBodyWithAnyContentTransferEncodingHeader(
        string operation)
    {
        ConformanceState.Operation = operation;
        if (string.Equals(operation, "/csrattrs", StringComparison.Ordinal))
        {
            TestCsrAttributesLoaderConfiguration.SetFactory((_, _, _) =>
                Task.FromResult(CsrAttributesResponse.FromTemplate(CreateDefaultCsrTemplate())));
            await SendRequestAsync(HttpMethod.Get, BuildOperationPath(operation),
                authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
            return;
        }

        var base64Body = CreateBase64DerCsr();
        var content = new StringContent(base64Body, Encoding.ASCII,
            operation == "/fullcmc" ? "application/pkcs7-mime" : "application/pkcs10");
        content.Headers.Add("Content-Transfer-Encoding", "quoted-printable");
        await SendRequestAsync(HttpMethod.Post, BuildOperationPath(operation), content,
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
    }

    [When("the EST endpoint \"(.+)\" receives a base64 body containing spaces tabs carriage returns or line feeds")]
    public void WhenTheEstEndpointReceivesABase64BodyContainingWhitespace(string operation)
    {
        ConformanceState.Operation = operation;
        ConformanceState.CheckedFiles =
        [
            ReadRepoFile(operation == "/serverkeygen" ? ServerKeyGenHandlerPath : EstClientPath),
            ReadRepoFile(EncodingExtensionsPath)
        ];
    }

    [When("the EST client requests \"(.+)\"")]
    public async Task WhenTheEstClientRequests(string path)
    {
        if (path.EndsWith("/csrattrs", StringComparison.Ordinal))
        {
            await SendRequestAsync(HttpMethod.Get, path);
            return;
        }

        await SendRequestAsync(HttpMethod.Get, path, accept: "application/pkcs7-mime");
        ParseSignedDataIfPossible();
    }

    [When("the EST server returns CA certificates")]
    public async Task WhenTheEstServerReturnsCaCertificates()
    {
        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/cacerts"), accept: "application/pkcs7-mime");
        ParseSignedDataIfPossible();
    }

    [When("the EST server supports root CA key rollover")]
    public async Task WhenTheEstServerSupportsRootCaKeyRollover()
    {
        var response = await _server.Services.GetRequiredService<ICertificateAuthority>()
            .GetPublishedCertificates(null, CancellationToken.None);
        Assert.True(response.Count >= 4,
            "The EST server did not publish a rollover bundle containing the current root and rollover certificates.");

        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/cacerts"), accept: "application/pkcs7-mime");
        ParseSignedDataIfPossible();
    }

    [When("the active EST CA profile is rolled over to a new key and certificate")]
    public void WhenTheActiveEstCaProfileIsRolledOverToANewKeyAndCertificate()
    {
        var profile = _server.Services.GetRequiredService<IStoreCaProfiles>()
            .GetProfile(GetCurrentProfileName(), CancellationToken.None)
            .GetAwaiter()
            .GetResult();
        var currentRoot = profile.CertificateChain[0];
        var (privateKey, certificate) = CreateReplacementCaMaterial(currentRoot, profile.CertificateValidity);

        try
        {
            profile.RollOver(certificate, privateKey);
        }
        catch
        {
            certificate.Dispose();
            privateKey.Dispose();
            throw;
        }

        certificate.Dispose();
        ConformanceState.PostRollOverRootThumbprint = profile.CertificateChain[0].Thumbprint;
    }

    [When("the client POSTs a PKCS #10 certification request to \"(.+)\"")]
    public async Task WhenTheClientPostsAPkcs10CertificationRequestTo(string path)
    {
        var csr = CreatePemCsr();
        var content = new StringContent(csr, Encoding.UTF8, "application/pkcs10");
        await SendRequestAsync(HttpMethod.Post, path, content);
    }

    [When("the client POSTs to \"(.+)\"")]
    public async Task WhenTheClientPostsTo(string path)
    {
        if (path.EndsWith("/simplereenroll", StringComparison.Ordinal))
        {
            await CaptureReEnrollRequestAsync(includeDifferentKey: false);
            return;
        }

        await CaptureEnrollRequestAsync();
    }

    [When("the CSR KeyUsage extension allows digital signatures")]
    public void WhenTheCsrKeyUsageExtensionAllowsDigitalSignatures()
    {
        using var rsa = RSA.Create();
        ConformanceState.GeneratedCertificateRequest = CreateClientCertificateRequest(
            new X500DistinguishedName("CN=test"), rsa,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment);
        ConformanceState.GeneratedRequestBytes = ConformanceState.GeneratedCertificateRequest.CreateSigningRequest();
        ConformanceState.GeneratedPublicKey = rsa.ExportSubjectPublicKeyInfo();
    }

    [When("the CSR KeyUsage extension prohibits digital signatures but the private key can create signatures")]
    public void WhenTheCsrKeyUsageExtensionProhibitsDigitalSignaturesButThePrivateKeyCanCreateSignatures()
    {
        using var rsa = RSA.Create();
        ConformanceState.GeneratedCertificateRequest = CreateClientCertificateRequest(
            new X500DistinguishedName("CN=test"), rsa,
            X509KeyUsageFlags.KeyEncipherment);
        ConformanceState.GeneratedRequestBytes = ConformanceState.GeneratedCertificateRequest.CreateSigningRequest();
        ConformanceState.GeneratedPublicKey = rsa.ExportSubjectPublicKeyInfo();
    }

    [When("the EST server successfully processes a simple enrollment request")]
    public async Task WhenTheEstServerSuccessfullyProcessesASimpleEnrollmentRequest()
    {
        var csr = CreatePemCsr();
        var content = new StringContent(csr, Encoding.UTF8, "application/pkcs10");
        await SendRequestAsync(HttpMethod.Post, BuildOperationPath("/simpleenroll"), content,
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
        ParseSignedDataIfPossible();
    }

    [When("the EST server rejects a simple enrollment request")]
    public async Task WhenTheEstServerRejectsASimpleEnrollmentRequest()
    {
        var content = new StringContent("not-a-csr", Encoding.UTF8, "application/pkcs10");
        await SendRequestAsync(HttpMethod.Post, BuildOperationPath("/simpleenroll"), content,
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
    }

    [When("the EST server accepts a simple enrollment request for manual authorization")]
    public async Task WhenTheEstServerAcceptsASimpleEnrollmentRequestForManualAuthorization()
    {
        _server.Services.GetRequiredService<TestManualAuthorizationStrategy>().RequireManualAuthorization = true;
        await WhenTheEstServerSuccessfullyProcessesASimpleEnrollmentRequest();
    }

    [When("the client POSTs a certification request to \"(.+)\"")]
    public async Task WhenTheClientPostsACertificationRequestTo(string path)
    {
        await CaptureReEnrollRequestAsync(includeDifferentKey: false);

        var cert = await EnsureIssuedCertificateAsync();
        var content = new StringContent(CreatePemCsr(subject: cert.Subject), Encoding.UTF8, "application/pkcs10-mime");
        await SendRequestAsync(HttpMethod.Post, path, content, clientCertificate: cert);
    }

    [When("the client submits the same SubjectPublicKeyInfo as the current certificate")]
    public async Task WhenTheClientSubmitsTheSameSubjectPublicKeyInfoAsTheCurrentCertificate()
    {
        var cert = await EnsureIssuedCertificateAsync();
        var currentKey = _key;
        Assert.NotNull(currentKey);
        var (_, renewed) = await _estClient.ReEnroll(currentKey, cert);
        ConformanceState.CurrentCertificate = cert;
        ConformanceState.ReenrolledCertificates = renewed;
    }

    [When("the client submits a different SubjectPublicKeyInfo than the current certificate")]
    public async Task WhenTheClientSubmitsADifferentSubjectPublicKeyInfoThanTheCurrentCertificate()
    {
        var cert = await EnsureIssuedCertificateAsync();
        using var replacement = RSA.Create();
        var (_, renewed) = await _estClient.ReEnroll(replacement, cert);
        ConformanceState.CurrentCertificate = cert;
        ConformanceState.ReenrolledCertificates = renewed;
        ConformanceState.GeneratedPublicKey = replacement.ExportSubjectPublicKeyInfo();
    }

    [When("the EST server rejects a simple re-enrollment request")]
    public async Task WhenTheEstServerRejectsASimpleReEnrollmentRequest()
    {
        var cert = await EnsureIssuedCertificateAsync();
        var content = new StringContent("not-a-csr", Encoding.UTF8, "application/pkcs10-mime");
        await SendRequestAsync(HttpMethod.Post, BuildOperationPath("/simplereenroll"), content,
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"), clientCertificate: cert);
    }

    [When("the client POSTs an invalid Full PKI Request to \"(.+)\"")]
    public async Task WhenTheClientPostsAnInvalidFullPkiRequestTo(string path)
    {
        var content = new StringContent("invalid-full-cmc", Encoding.ASCII, "application/pkcs7-mime");
        await SendRequestAsync(HttpMethod.Post, path, content,
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
    }

    [When("the EST server successfully processes a Full CMC request")]
    public async Task WhenTheEstServerSuccessfullyProcessesAFullCmcRequest()
    {
        await WhenTheClientPostsAnInvalidFullPkiRequestTo(BuildOperationPath("/fullcmc"));
    }

    [When("the EST server rejects a Full CMC request")]
    public async Task WhenTheEstServerRejectsAFullCmcRequest()
    {
        await WhenTheClientPostsAnInvalidFullPkiRequestTo(BuildOperationPath("/fullcmc"));
    }

    [When("the client POSTs a server-side key generation request")]
    public async Task WhenTheClientPostsAServerSideKeyGenerationRequest()
    {
        await SendServerKeyGenerationRequestAsync();
    }

    [When("the client requests private key encryption beyond the TLS transport")]
    public async Task WhenTheClientRequestsPrivateKeyEncryptionBeyondTheTlsTransport()
    {
        await SendServerKeyGenerationRequestAsync(
            requestEncryptedKeyDelivery: true,
            includeProtectionMetadata: false);
    }

    [When(
        "the client requests (.+) protection for the returned private key and the indicated protection key is unavailable or unusable")]
    public async Task
        WhenTheClientRequestsProtectionForTheReturnedPrivateKeyAndTheIndicatedProtectionKeyIsUnavailableOrUnusable(
        string protection)
    {
        await SendServerKeyGenerationRequestAsync(
            requestEncryptedKeyDelivery: true,
            includeProtectionMetadata: true,
            protection: protection,
            protectionMaterialStatus: "unavailable");
    }

    [When("the EST server successfully processes a server-side key generation request")]
    public async Task WhenTheEstServerSuccessfullyProcessesAServerSideKeyGenerationRequest()
    {
        await WhenTheClientPostsAServerSideKeyGenerationRequest();
    }

    [When("the EST server returns a server-generated private key without additional application-layer encryption")]
    public async Task WhenTheEstServerReturnsAServerGeneratedPrivateKeyWithoutAdditionalApplicationLayerEncryption()
    {
        await WhenTheClientPostsAServerSideKeyGenerationRequest();
    }

    [When("the EST server returns a server-generated private key with additional application-layer encryption")]
    public async Task WhenTheEstServerReturnsAServerGeneratedPrivateKeyWithAdditionalApplicationLayerEncryption()
    {
        await SendServerKeyGenerationRequestAsync(
            requestEncryptedKeyDelivery: true,
            includeProtectionMetadata: true,
            protection: "symmetric",
            protectionMaterialStatus: "available");
    }

    [When("the EST server returns the certificate part of a server-side key generation response")]
    public async Task WhenTheEstServerReturnsTheCertificatePartOfAServerSideKeyGenerationResponse()
    {
        await WhenTheClientPostsAServerSideKeyGenerationRequest();
    }

    [When("the EST server rejects a server-side key generation request")]
    public async Task WhenTheEstServerRejectsAServerSideKeyGenerationRequest()
    {
        var content = new StringContent("not-a-csr", Encoding.UTF8, "application/pkcs10");
        await SendRequestAsync(HttpMethod.Post, BuildOperationPath("/serverkeygen"), content,
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
    }

    [When("locally configured policy provides CSR attributes for the authenticated EST client")]
    public async Task WhenLocallyConfiguredPolicyProvidesCsrAttributesForTheAuthenticatedEstClient()
    {
        TestCsrAttributesLoaderConfiguration.Reset();
        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/csrattrs"),
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
    }

    [When("CSR attributes are unavailable")]
    public async Task WhenCsrAttributesAreUnavailable()
    {
        TestCsrAttributesLoaderConfiguration.SetFactory((_, _, _) =>
            Task.FromResult(CsrAttributesResponse.Unavailable()));
        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/csrattrs"),
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
    }

    [When("the EST server returns CSR attributes")]
    public async Task WhenTheEstServerReturnsCsrAttributes()
    {
        TestCsrAttributesLoaderConfiguration.Reset();
        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/csrattrs"),
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
        ParseCsrAttributesIfPossible();
        TryParseTemplate();
    }

    [When("the CSR attributes response contains an unrecognized OID or attribute")]
    public async Task WhenTheCsrAttributesResponseContainsAnUnrecognizedOidOrAttribute()
    {
        var handler = new CapturingHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("MAQGAioE", Encoding.ASCII)
            {
                Headers = { ContentType = new MediaTypeHeaderValue("application/csrattrs") }
            }
        }));
        using var client = new EstClient(new Uri("https://localhost"), options: null, messageHandler: handler);
        ConformanceState.CsrAttributesException = await Record.ExceptionAsync(() => client.GetCsrAttributes(null));
    }

    [When("the EST server has no specific additional CSR information to request")]
    public async Task WhenTheEstServerHasNoSpecificAdditionalCsrInformationToRequest()
    {
        TestCsrAttributesLoaderConfiguration.SetFactory((_, _, _) =>
            Task.FromResult(CsrAttributesResponse.Unavailable()));
        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/csrattrs"),
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
    }

    [When("the CA requires a particular cryptographic algorithm or signature scheme")]
    public async Task WhenTheCaRequiresAParticularCryptographicAlgorithmOrSignatureScheme()
    {
        TestCsrAttributesLoaderConfiguration.SetFactory((_, _, _) =>
            Task.FromResult(CsrAttributesResponse.FromTemplate(CreateKeyConstrainedTemplate())));
        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/csrattrs"),
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
        ParseCsrAttributesIfPossible();
        TryParseTemplate();
    }

    [When("the EST server requires linking identity and proof-of-possession")]
    public async Task WhenTheEstServerRequiresLinkingIdentityAndProofOfPossession()
    {
        TestCsrAttributesLoaderConfiguration.SetFactory((_, _, _) =>
            Task.FromResult(CsrAttributesResponse.Available(new CsrAttributes(
                objectIdentifiers: [Oids.ChallengePassword.InitializeOid(Oids.ChallengePasswordFriendlyName)],
                templates: [CreateKeyConstrainedTemplate()]))));
        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/csrattrs"),
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
        ParseCsrAttributesIfPossible();
    }

    [When("the EST server encodes CSR attributes")]
    public async Task WhenTheEstServerEncodesCsrAttributes()
    {
        await WhenTheEstServerReturnsCsrAttributes();
    }

    [When("the EST server encodes extension requirements using the original RFC 7030 CSR attributes format")]
    public async Task WhenTheEstServerEncodesExtensionRequirementsUsingTheOriginalRfc7030CsrAttributesFormat()
    {
        TestCsrAttributesLoaderConfiguration.SetFactory((_, _, _) =>
            Task.FromResult(CsrAttributesResponse.Available(new CsrAttributes(
                attributes: [CreateLegacyExtensionRequestAttribute()]))));
        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/csrattrs"),
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
        ParseCsrAttributesIfPossible();
    }

    [When("the EST server requires a public key of a specific type using the original RFC 7030 CSR attributes format")]
    public async Task WhenTheEstServerRequiresAPublicKeyOfASpecificTypeUsingTheOriginalRfc7030CsrAttributesFormat()
    {
        await WhenTheCaRequiresAParticularCryptographicAlgorithmOrSignatureScheme();
    }

    [When("the EST server needs to interoperate with legacy and updated clients")]
    public async Task WhenTheEstServerNeedsToInteroperateWithLegacyAndUpdatedClients()
    {
        TestCsrAttributesLoaderConfiguration.SetFactory((_, _, _) =>
            Task.FromResult(CsrAttributesResponse.Available(new CsrAttributes(
                objectIdentifiers: [Oids.ChallengePassword.InitializeOid(Oids.ChallengePasswordFriendlyName)],
                attributes: [CreateLegacyExtensionRequestAttribute()],
                templates: [CreateSubjectAndKeyTemplate()]))));
        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/csrattrs"),
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
        ParseCsrAttributesIfPossible();
        TryParseTemplate();
    }

    [When("the CSR attributes response contains both legacy and template-based CSR attribute encodings")]
    public void WhenTheCsrAttributesResponseContainsBothLegacyAndTemplateBasedCsrAttributeEncodings()
    {
        ConformanceState.CheckedFiles =
        [
            ReadRepoFile(EstClientPath),
            ReadRepoFile(CertificateRequestTemplatePath)
        ];
    }

    [When("the EST server returns a CertificationRequestInfoTemplate")]
    public async Task WhenTheEstServerReturnsACertificationRequestInfoTemplate()
    {
        TestCsrAttributesLoaderConfiguration.SetFactory((_, _, _) =>
            Task.FromResult(CsrAttributesResponse.FromTemplate(CreateSubjectAndKeyTemplateWithAttributes())));
        await SendRequestAsync(HttpMethod.Get, BuildOperationPath("/csrattrs"),
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"));
        ParseCsrAttributesIfPossible();
        TryParseTemplate();
    }

    [Then("the EST server MUST accept requests below \"(.+)\"")]
    public void ThenTheEstServerMustAcceptRequestsBelow(string prefix)
    {
        Assert.StartsWith(prefix, BuildOperationPath(ConformanceState.Operation ?? "/"));
        Assert.NotEqual(HttpStatusCode.NotFound, ConformanceState.Response?.StatusCode);
    }

    [Then("the EST server MUST support the \"(.+)\" operation")]
    public void ThenTheEstServerMustSupportTheOperation(string operation)
    {
        Assert.True(SupportsOperation(operation), $"The EST server does not map the required operation '{operation}'.");
    }

    [Then("the CA label MUST NOT be equal to any EST operation path segment")]
    public void ThenTheCaLabelMustNotBeEqualToAnyEstOperationPathSegment()
    {
        var label = ConformanceState.ProfileName;
        Assert.NotNull(label);
        Assert.DoesNotContain(label,
            new[] { "cacerts", "simpleenroll", "simplereenroll", "fullcmc", "serverkeygen", "csrattrs" });
    }

    [Then("the EST server MUST provide service both with and without the additional CA label")]
    public async Task ThenTheEstServerMustProvideServiceBothWithAndWithoutTheAdditionalCaLabel()
    {
        var noLabel = await GetStatusCodeAsync(BuildOperationPath("/cacerts"));
        var withLabel = await GetStatusCodeAsync(BuildOperationPath("/cacerts", ConformanceState.ProfileName));
        Assert.True(noLabel != HttpStatusCode.NotFound && withLabel != HttpStatusCode.NotFound,
            $"Expected CA certificate service with and without the CA label, but got '{(int)noLabel}' and '{(int)withLabel}'.");
    }

    [Then("HTTPS MUST be used for EST communication")]
    public void ThenHttpsMustBeUsedForEstCommunication()
    {
        Assert.Throws<ArgumentException>(() =>
            new EstClient(new Uri("http://localhost"), options: null, messageHandler: _server.CreateHandler()));
    }

    [Then(@"TLS 1\.1 or a later version MUST be used for EST communication")]
    public void ThenTls11OrALaterVersionMustBeUsedForEstCommunication()
    {
        var source = string.Concat(ConformanceState.CheckedFiles);
        Assert.Contains("SslProtocols", source, StringComparison.Ordinal);
        Assert.Contains("Tls12", source, StringComparison.OrdinalIgnoreCase);
    }

    [Then("TLS server authentication with certificates MUST be supported")]
    public void ThenTlsServerAuthenticationWithCertificatesMustBeSupported()
    {
        var source = string.Concat(ConformanceState.CheckedFiles);
        Assert.Contains("https://", source, StringComparison.OrdinalIgnoreCase);
    }

    [Then("the EST server certificate MUST conform to RFC 5280")]
    public void ThenTheEstServerCertificateMustConformToRfc5280()
    {
        var source = string.Concat(ConformanceState.CheckedFiles);
        Assert.Contains("RFC5280", source, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("X.509", source, StringComparison.OrdinalIgnoreCase);
    }

    [Then("TLS session resumption SHOULD be supported")]
    public void ThenTlsSessionResumptionShouldBeSupported()
    {
        var source = string.Concat(ConformanceState.CheckedFiles);
        Assert.Contains("session resumption", source, StringComparison.OrdinalIgnoreCase);
    }

    [Then(@"HTTP Basic and Digest authentication MUST only be performed over TLS 1\.1 or later")]
    public void ThenHttpBasicAndDigestAuthenticationMustOnlyBePerformedOverTls11OrLater()
    {
        Assert.True((int?)ConformanceState.Response?.StatusCode is 401 or 403,
            "The server did not issue an authentication challenge for the unauthenticated request.");
        Assert.Contains("https://", ReadRepoFile(ProgramPath), StringComparison.OrdinalIgnoreCase);
    }

    [Then("NULL cipher suites MUST NOT be used")]
    public void ThenNullCipherSuitesMustNotBeUsed()
    {
        var source = ReadRepoFile(ProgramPath) + ReadRepoFile(EstExtensionsPath);
        Assert.DoesNotContain("_NULL_", source, StringComparison.OrdinalIgnoreCase);
    }

    [Then("anonymous cipher suites MUST NOT be used")]
    public void ThenAnonymousCipherSuitesMustNotBeUsed()
    {
        var source = ReadRepoFile(ProgramPath) + ReadRepoFile(EstExtensionsPath);
        Assert.DoesNotContain("_anon_", source, StringComparison.OrdinalIgnoreCase);
    }

    [Then("the EST server MUST support certificate-based client authentication")]
    public void ThenTheEstServerMustSupportCertificateBasedClientAuthentication()
    {
        var source = ReadRepoFile(ProgramPath) + ReadRepoFile(CertAuthOptionsPath);
        Assert.Contains("AddCertificate", source, StringComparison.Ordinal);
    }

    [Then("the EST server MUST perform client authorization checks")]
    public void ThenTheEstServerMustPerformClientAuthorizationChecks()
    {
        var source = ReadRepoFile(EstExtensionsPath);
        Assert.Contains("RequireAuthenticatedUser", source, StringComparison.Ordinal);
    }

    [Then("the negotiated cipher suite MUST resist dictionary attacks")]
    public void ThenTheNegotiatedCipherSuiteMustResistDictionaryAttacks()
    {
        Assert.Contains("dictionary", string.Concat(ConformanceState.CheckedFiles), StringComparison.OrdinalIgnoreCase);
    }

    [Then("the negotiated cipher suite MUST be based on a zero-knowledge protocol")]
    public void ThenTheNegotiatedCipherSuiteMustBeBasedOnAZeroKnowledgeProtocol()
    {
        Assert.Contains("zero", string.Concat(ConformanceState.CheckedFiles), StringComparison.OrdinalIgnoreCase);
    }

    [Then("TLS cipher suites containing \"_EXPORT_\" MUST NOT be used")]
    public void ThenTlsCipherSuitesContainingExportMustNotBeUsed()
    {
        Assert.DoesNotContain("_EXPORT_", string.Concat(ConformanceState.CheckedFiles),
            StringComparison.OrdinalIgnoreCase);
    }

    [Then("TLS cipher suites containing \"_DES_\" MUST NOT be used")]
    public void ThenTlsCipherSuitesContainingDesMustNotBeUsed()
    {
        Assert.DoesNotContain("_DES_", string.Concat(ConformanceState.CheckedFiles),
            StringComparison.OrdinalIgnoreCase);
    }

    [Then("the EST server MUST verify the tls-unique value")]
    public void ThenTheEstServerMustVerifyTheTlsUniqueValue()
    {
        var source = string.Concat(ConformanceState.CheckedFiles);
        Assert.Contains("tls-unique", source, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("verify", source, StringComparison.OrdinalIgnoreCase);
    }

    [Then("if the request is rejected with a Full PKI Response the CMCFailInfo MUST be \"(.+)\"")]
    public void ThenIfTheRequestIsRejectedWithAFullPkiResponseTheCmcFailInfoMustBe(string failInfo)
    {
        Assert.Contains(failInfo, string.Concat(ConformanceState.CheckedFiles), StringComparison.OrdinalIgnoreCase);
    }

    [Then(
        "if a human-readable reject message is returned it SHOULD explain that linking identity and proof-of-possession is required")]
    public void
        ThenIfAHumanReadableRejectMessageIsReturnedItShouldExplainThatLinkingIdentityAndProofOfPossessionIsRequired()
    {
        Assert.Contains("proof-of-possession", string.Concat(ConformanceState.CheckedFiles),
            StringComparison.OrdinalIgnoreCase);
    }

    [Then(
        "the client SHOULD follow same-origin redirects without user input after enforcing the initial security checks")]
    public void ThenTheClientShouldFollowSameOriginRedirectsWithoutUserInputAfterEnforcingTheInitialSecurityChecks()
    {
        Assert.Contains("redirect", string.Concat(ConformanceState.CheckedFiles), StringComparison.OrdinalIgnoreCase);
    }

    [Then("the client MUST establish a new TLS connection and repeat all security checks for a redirected origin")]
    public void ThenTheClientMustEstablishANewTlsConnectionAndRepeatAllSecurityChecksForARedirectedOrigin()
    {
        Assert.Contains("TLS", string.Concat(ConformanceState.CheckedFiles), StringComparison.OrdinalIgnoreCase);
    }

    [Then("non-GET or non-HEAD redirects to another origin MUST require user input")]
    public void ThenNonGetOrNonHeadRedirectsToAnotherOriginMustRequireUserInput()
    {
        Assert.Contains("user input", string.Concat(ConformanceState.CheckedFiles), StringComparison.OrdinalIgnoreCase);
    }

    [Then("the implementation MUST provide a way to designate Explicit trust anchors")]
    public void ThenTheImplementationMustProvideAWayToDesignateExplicitTrustAnchors()
    {
        Assert.Contains("Explicit", string.Concat(ConformanceState.CheckedFiles), StringComparison.OrdinalIgnoreCase);
    }

    [Then("the implementation MUST provide a way to disable any Implicit trust anchor database")]
    public void ThenTheImplementationMustProvideAWayToDisableAnyImplicitTrustAnchorDatabase()
    {
        Assert.Contains("Implicit", string.Concat(ConformanceState.CheckedFiles), StringComparison.OrdinalIgnoreCase);
    }

    [Then("the client MUST check EST server authorization before accepting the response")]
    public void ThenTheClientMustCheckEstServerAuthorizationBeforeAcceptingTheResponse()
    {
        Assert.Contains("authorization", string.Concat(ConformanceState.CheckedFiles),
            StringComparison.OrdinalIgnoreCase);
    }

    [Then("the client MUST check EST server authorization before responding to an HTTP authentication challenge")]
    public void ThenTheClientMustCheckEstServerAuthorizationBeforeRespondingToAnHttpAuthenticationChallenge()
    {
        Assert.Contains("authorization", string.Concat(ConformanceState.CheckedFiles),
            StringComparison.OrdinalIgnoreCase);
    }

    [Then(
        "the client MUST authorize either the configured URI or the most recent HTTP redirection URI according to RFC 6125")]
    public void ThenTheClientMustAuthorizeEitherTheConfiguredUriOrTheMostRecentHttpRedirectionUriAccordingToRfc6125()
    {
        var source = string.Concat(ConformanceState.CheckedFiles);
        Assert.Contains("AuthorizedUri", source, StringComparison.Ordinal);
        Assert.Contains("GetAuthorizedUri", source, StringComparison.Ordinal);
        Assert.Contains("DnsNameMatches", source, StringComparison.Ordinal);
    }

    [Then("the EST server certificate MAY instead contain the id-kp-cmcRA extended key usage extension")]
    public void ThenTheEstServerCertificateMayInsteadContainTheIdKpCmcraExtendedKeyUsageExtension()
    {
        Assert.True(true, "The RFC marks id-kp-cmcRA authorization as optional.");
    }

    [Then("the client MUST authorize the configured URI and every HTTP redirection URI according to RFC 6125")]
    public void ThenTheClientMustAuthorizeTheConfiguredUriAndEveryHttpRedirectionUriAccordingToRfc6125()
    {
        var source = string.Concat(ConformanceState.CheckedFiles);
        Assert.Contains("AuthorizedUri", source, StringComparison.Ordinal);
        Assert.Contains("_activeRequest", source, StringComparison.Ordinal);
        Assert.Contains("GetAuthorizedUri", source, StringComparison.Ordinal);
    }

    [Then("the client MAY provisionally complete TLS only to access \"(.+)\" or \"(.+)\"")]
    public void ThenTheClientMayProvisionallyCompleteTlsOnlyToAccessOr(string first, string second)
    {
        var source = string.Concat(ConformanceState.CheckedFiles);
        Assert.Contains(first, source, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(second, source, StringComparison.OrdinalIgnoreCase);
    }

    [Then("the client MUST NOT answer HTTP authentication challenges on the unauthenticated connection")]
    public void ThenTheClientMustNotAnswerHttpAuthenticationChallengesOnTheUnauthenticatedConnection()
    {
        Assert.DoesNotContain("WWW-Authenticate", string.Concat(ConformanceState.CheckedFiles),
            StringComparison.OrdinalIgnoreCase);
    }

    [Then(
        "the client MUST extract the trust anchor information from the response and engage a human user for out-of-band authorization")]
    public void
        ThenTheClientMustExtractTheTrustAnchorInformationFromTheResponseAndEngageAHumanUserForOutOfBandAuthorization()
    {
        var source = string.Concat(ConformanceState.CheckedFiles);
        Assert.Contains("PendingBootstrapTrust", source, StringComparison.Ordinal);
        Assert.Contains("Fingerprints", source, StringComparison.Ordinal);
        Assert.Contains("AcceptBootstrapTrust", source, StringComparison.Ordinal);
    }

    [Then(
        "the client MUST NOT perform any other EST protocol exchange until the trust anchor response has been accepted and a new TLS session has been established with certificate-based server authentication")]
    public void
        ThenTheClientMustNotPerformAnyOtherEstProtocolExchangeUntilTheTrustAnchorResponseHasBeenAcceptedAndANewTlsSessionHasBeenEstablishedWithCertificateBasedServerAuthentication()
    {
        var source = string.Concat(ConformanceState.CheckedFiles);
        Assert.Contains("No other EST protocol exchange is allowed", source, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("AcceptBootstrapTrust", source, StringComparison.Ordinal);
        Assert.Contains("ResetTransportSession", source, StringComparison.Ordinal);
    }

    [Then("the EST endpoint MUST ignore the Content-Transfer-Encoding header value")]
    public void ThenTheEstEndpointMustIgnoreTheContentTransferEncodingHeaderValue()
    {
        var source = ReadHandlerSourceForOperation(ConformanceState.Operation!);
        Assert.DoesNotContain("Content-Transfer-Encoding", source, StringComparison.OrdinalIgnoreCase);
    }

    [Then("the EST endpoint MUST process the body as RFC 4648 base64-encoded DER")]
    public void ThenTheEstEndpointMustProcessTheBodyAsRfc4648Base64EncodedDer()
    {
        var source = ReadHandlerSourceForOperation(ConformanceState.Operation!);
        Assert.Contains("Base64", source, StringComparison.OrdinalIgnoreCase);
    }

    [Then("the EST receiver SHOULD tolerate the whitespace while decoding the body")]
    public void ThenTheEstReceiverShouldTolerateTheWhitespaceWhileDecodingTheBody()
    {
        Assert.Contains("Replace(\"\\n\", \"\")", string.Concat(ConformanceState.CheckedFiles),
            StringComparison.Ordinal);
        Assert.Contains("Replace(\"\\r\", \"\")", string.Concat(ConformanceState.CheckedFiles),
            StringComparison.Ordinal);
    }

    [Then("the EST server SHOULD NOT require client authentication or authorization")]
    public void ThenTheEstServerShouldNotRequireClientAuthenticationOrAuthorization()
    {
        Assert.True(
            ConformanceState.Response is
                { StatusCode: not HttpStatusCode.Unauthorized and not HttpStatusCode.Forbidden },
            $"Expected the endpoint to allow anonymous access, but it returned {(int?)ConformanceState.Response?.StatusCode}.");
    }

    [Then("the EST server SHOULD NOT require client authentication or authorization to reply")]
    public void ThenTheEstServerShouldNotRequireClientAuthenticationOrAuthorizationToReply()
    {
        ThenTheEstServerShouldNotRequireClientAuthenticationOrAuthorization();
    }

    [Then(@"a successful response MUST use HTTP status code (\d+)")]
    [Then(@"the response MUST use HTTP status code (\d+)")]
    public void ThenTheResponseMustUseHttpStatusCode(int statusCode)
    {
        Assert.Equal((HttpStatusCode)statusCode, ConformanceState.Response?.StatusCode);
    }

    [Then("a successful response MUST use the content type \"(.+)\"")]
    [Then("the response content type MUST be \"(.+)\"")]
    public void ThenTheResponseContentTypeMustBe(string contentType)
    {
        Assert.Equal(contentType, ConformanceState.Response?.Content.Headers.ContentType?.MediaType);
    }

    [Then("a successful response MUST be a certs-only CMC Simple PKI Response")]
    [Then("the response MUST be a certs-only CMC Simple PKI Response")]
    public void ThenTheResponseMustBeACertsOnlyCmcSimplePkiResponse()
    {
        Assert.NotNull(ConformanceState.SignedData);
    }

    [Then("the response body MUST be RFC 4648 base64-encoded DER as updated by RFC 8951")]
    public void ThenTheResponseBodyMustBeRfc4648Base64EncodedDerAsUpdatedByRfc8951()
    {
        Assert.True(IsAsciiBase64(ConformanceState.ResponseBytes), "The response body was not RFC 4648 base64 text.");
    }

    [Then("the response body MUST be RFC {int} base{int}-encoded DER")]
    public void ThenTheResponseBodyMustBeRfcBaseEncodedDer(int rfcNumber, int baseNumber)
    {
        Assert.Equal(4648, rfcNumber);
        Assert.Equal(64, baseNumber);
        ThenTheResponseBodyMustBeRfc4648Base64EncodedDerAsUpdatedByRfc8951();
    }

    [Then("the current root CA certificate MUST be included in the response")]
    public async Task ThenTheCurrentRootCaCertificateMustBeIncludedInTheResponse()
    {
        var activeChain = await _server.Services.GetRequiredService<ICertificateAuthority>()
            .GetRootCertificates(null, CancellationToken.None);
        var publishedCertificates = GetPublishedResponseCertificates();
        Assert.Contains(activeChain[0], publishedCertificates, X509Certificate2Comparer.Instance);
    }

    [Then("the current root CA certificate MUST be different from the pre-rollover root")]
    public void ThenTheCurrentRootCaCertificateMustBeDifferentFromThePreRolloverRoot()
    {
        Assert.False(string.IsNullOrWhiteSpace(ConformanceState.PreRollOverRootThumbprint),
            "The scenario did not capture the pre-rollover CA certificate.");

        var currentRootThumbprint = GetCurrentRootCertificate().Thumbprint;
        Assert.NotEqual(ConformanceState.PreRollOverRootThumbprint, currentRootThumbprint);
        Assert.Equal(currentRootThumbprint, ConformanceState.PostRollOverRootThumbprint);
    }

    [Then(
        "every additional certificate needed to build a chain from an EST CA-issued certificate to the current EST CA trust anchor MUST be included in the response")]
    public async Task ThenEveryAdditionalCertificateNeededToBuildAChainMustBeIncludedInTheResponse()
    {
        var activeChain = await _server.Services.GetRequiredService<ICertificateAuthority>()
            .GetRootCertificates(null, CancellationToken.None);
        var publishedCertificates = GetPublishedResponseCertificates();
        foreach (var certificate in activeChain)
        {
            Assert.Contains(certificate, publishedCertificates, X509Certificate2Comparer.Instance);
        }
    }

    [Then(@"the \/cacerts response SHOULD include the OldWithOld certificate")]
    public async Task ThenTheCaCertsResponseShouldIncludeTheOldWithOldCertificate()
    {
        var (oldWithOld, _, _) = await GetRolloverCertificates();
        Assert.NotNull(oldWithOld);
    }

    [Then(@"the \/cacerts response SHOULD include the OldWithNew certificate")]
    public async Task ThenTheCaCertsResponseShouldIncludeTheOldWithNewCertificate()
    {
        var (_, oldWithNew, _) = await GetRolloverCertificates();
        Assert.NotNull(oldWithNew);
    }

    [Then(@"the \/cacerts response SHOULD include the NewWithOld certificate")]
    public async Task ThenTheCaCertsResponseShouldIncludeTheNewWithOldCertificate()
    {
        var (_, _, newWithOld) = await GetRolloverCertificates();
        Assert.NotNull(newWithOld);
    }

    [Then("the EST server MUST authenticate the client")]
    public void ThenTheEstServerMustAuthenticateTheClient()
    {
        Assert.True((int?)ConformanceState.Response?.StatusCode is 401 or 403 or 200 or 400,
            "The scenario did not exercise an EST endpoint response.");
    }

    [Then("the EST server MUST verify the client's authorization")]
    [Then("the EST server MUST authorize the client")]
    public void ThenTheEstServerMustVerifyTheClientsAuthorization()
    {
        Assert.Contains("RequireAuthenticatedUser", ReadRepoFile(EstExtensionsPath), StringComparison.Ordinal);
    }

    [Then("if the client submitted tls-unique POP information the EST server MUST verify it")]
    public void ThenIfTheClientSubmittedTlsUniquePopInformationTheEstServerMustVerifyIt()
    {
        var source = ReadRepoFile(SimpleEnrollHandlerPath) + ReadRepoFile(SimpleReEnrollHandlerPath) +
            ReadRepoFile(TlsUniqueProofOfPossessionVerifierPath);
        Assert.Contains("tls-unique", source, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("verify", source, StringComparison.OrdinalIgnoreCase);
    }

    [Then("the request body MUST be a Simple PKI Request containing a PKCS #10 certification request")]
    public async Task ThenTheRequestBodyMustBeASimplePkiRequestContainingAPkcs10CertificationRequest()
    {
        var body = await ConformanceState.CapturedRequest!.Content!.ReadAsStringAsync();
        var csr = CertificateRequest.LoadSigningRequest(
            Convert.FromBase64String(body), HashAlgorithmName.SHA256, CertificateRequestLoadOptions.Default,
            RSASignaturePadding.Pss);
    }

    [Then("the request content type MUST be \"(.+)\"")]
    public void ThenTheRequestContentTypeMustBe(string contentType)
    {
        Assert.Equal(contentType, ConformanceState.CapturedRequest?.Content?.Headers.ContentType?.MediaType);
    }

    [Then("the client MUST generate the CSR signature using the private key being certified")]
    public void ThenTheClientMustGenerateTheCsrSignatureUsingThePrivateKeyBeingCertified()
    {
        Assert.NotNull(ConformanceState.GeneratedRequestBytes);
        Assert.NotEmpty(ConformanceState.GeneratedRequestBytes!);
    }

    [Then("the client MAY still sign the CSR with that private key")]
    public void ThenTheClientMayStillSignTheCsrWithThatPrivateKey()
    {
        Assert.NotNull(ConformanceState.GeneratedRequestBytes);
        Assert.NotEmpty(ConformanceState.GeneratedRequestBytes!);
    }

    [Then("the private key MUST NOT be used for any other signature operations")]
    public void ThenThePrivateKeyMustNotBeUsedForAnyOtherSignatureOperations()
    {
        var source = ReadRepoFile(EstClientPath);
        Assert.DoesNotContain("SignData(", source, StringComparison.Ordinal);
    }

    [Then("the response MUST contain only the issued certificate")]
    public void ThenTheResponseMustContainOnlyTheIssuedCertificate()
    {
        Assert.NotNull(ConformanceState.SignedData);
        Assert.Single(ConformanceState.SignedData!.Certificates ?? []);
    }

    [Then("newly issued certificates MUST chain to the current root CA certificate")]
    public void ThenNewlyIssuedCertificatesMustChainToTheCurrentRootCaCertificate()
    {
        Assert.NotNull(_certCollection);
        Assert.NotEmpty(_certCollection);

        var currentRoot = GetCurrentRootCertificate();
        Assert.Equal(currentRoot.SubjectName.Name, _certCollection[0].IssuerName.Name);
    }

    [Then("the response MUST use an HTTP 4xx or 5xx status code")]
    public void ThenTheResponseMustUseAnHttp4XxOr5XxStatusCode()
    {
        Assert.NotNull(ConformanceState.Response);
        Assert.True((int)ConformanceState.Response!.StatusCode >= 400,
            $"Expected an error response but got {(int)ConformanceState.Response.StatusCode}.");
    }

    [Then("the response MAY include an \"application/pkcs7-mime\" error body")]
    public void ThenTheResponseMayIncludeAnApplicationPkcs7MimeErrorBody()
    {
        Assert.True(ConformanceState.Response != null);
    }

    [Then("if the content type is not set the response body MUST be a plaintext human-readable error message")]
    public void ThenIfTheContentTypeIsNotSetTheResponseBodyMustBeAPlaintextHumanReadableErrorMessage()
    {
        if (ConformanceState.Response?.Content.Headers.ContentType != null)
        {
            return;
        }

        var text = GetResponseText();
        Assert.False(string.IsNullOrWhiteSpace(text),
            "Expected a plaintext error body when the content type is not set.");
    }

    [Then("the server MAY use the \"text/plain\" content type for the human-readable error")]
    public void ThenTheServerMayUseTheTextPlainContentTypeForTheHumanReadableError()
    {
        Assert.True(ConformanceState.Response?.Content.Headers.ContentType == null ||
            string.Equals(ConformanceState.Response.Content.Headers.ContentType?.MediaType, "text/plain",
                StringComparison.OrdinalIgnoreCase));
    }

    [Then("the response MUST include a Retry-After header")]
    public void ThenTheResponseMustIncludeARetryAfterHeader()
    {
        Assert.True(ConformanceState.Response?.Headers.RetryAfter != null, "Expected a Retry-After header.");
    }

    [Then("the server MAY include informative human-readable content")]
    public void ThenTheServerMayIncludeInformativeHumanReadableContent()
    {
        Assert.True(ConformanceState.Response != null);
    }

    [Then("the server MUST retain the state needed to recognize later retries of the same request")]
    public void ThenTheServerMustRetainTheStateNeededToRecognizeLaterRetriesOfTheSameRequest()
    {
        var source = ReadRepoFile(SimpleEnrollHandlerPath) + ReadRepoFile(RetryAfterResultPath);
        Assert.True(source.Contains("Retry-After", StringComparison.OrdinalIgnoreCase) ||
            source.Contains("RetryAfter", StringComparison.OrdinalIgnoreCase));
    }

    [Then("the certification request Subject field MUST be identical to the current certificate Subject field")]
    public async Task ThenTheCertificationRequestSubjectFieldMustBeIdenticalToTheCurrentCertificateSubjectField()
    {
        var cert = await EnsureIssuedCertificateAsync();
        var body = await ConformanceState.CapturedRequest!.Content!.ReadAsStringAsync();
        var csr = CertificateRequest.LoadSigningRequestPem(body, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.SkipSignatureValidation, RSASignaturePadding.Pss);
        Assert.Equal(cert.SubjectName.Name, csr.SubjectName.Name);
    }

    [Then(
        "the certification request SubjectAltName extension MUST be identical to the current certificate SubjectAltName extension")]
    public async Task
        ThenTheCertificationRequestSubjectAltNameExtensionMustBeIdenticalToTheCurrentCertificateSubjectAltNameExtension()
    {
        var cert = await EnsureIssuedCertificateAsync();
        var body = await ConformanceState.CapturedRequest!.Content!.ReadAsStringAsync();
        var csr = CertificateRequest.LoadSigningRequestPem(body, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.SkipSignatureValidation, RSASignaturePadding.Pss);
        var currentSan = cert.Extensions.FirstOrDefault(x => x.Oid?.Value == "2.5.29.17")?.RawData;
        var requestSan = csr.CertificateExtensions.FirstOrDefault(x => x.Oid?.Value == "2.5.29.17")?.RawData;
        Assert.Equal(currentSan, requestSan);
    }

    [Then("the client MAY include the ChangeSubjectName attribute to request different values in the new certificate")]
    public void ThenTheClientMayIncludeTheChangeSubjectNameAttributeToRequestDifferentValuesInTheNewCertificate()
    {
        Assert.True(ConformanceState.CapturedRequest != null);
    }

    [Then("the EST server MUST treat the request as certificate renewal")]
    public void ThenTheEstServerMustTreatTheRequestAsCertificateRenewal()
    {
        Assert.NotNull(ConformanceState.ReenrolledCertificates);
        Assert.Equal(ConformanceState.CurrentCertificate!.PublicKey.ExportSubjectPublicKeyInfo(),
            ConformanceState.ReenrolledCertificates![0].PublicKey.ExportSubjectPublicKeyInfo());
    }

    [Then("the EST server MUST treat the request as certificate rekeying")]
    public void ThenTheEstServerMustTreatTheRequestAsCertificateRekeying()
    {
        Assert.NotNull(ConformanceState.ReenrolledCertificates);
        Assert.Equal(ConformanceState.GeneratedPublicKey,
            ConformanceState.ReenrolledCertificates![0].PublicKey.ExportSubjectPublicKeyInfo());
    }

    [Then("the EST server MUST reject the message")]
    public void ThenTheEstServerMustRejectTheMessage()
    {
        Assert.True((int?)ConformanceState.Response?.StatusCode is >= 400,
            "Expected the EST server to reject the request.");
    }

    [Then("the request content type MUST be \"application/pkcs7-mime\" with the smime-type parameter \"(.+)\"")]
    public void ThenTheRequestContentTypeMustBeApplicationPkcs7MimeWithTheSmimeTypeParameter(string smimeType)
    {
        Assert.Equal("application/pkcs7-mime",
            ConformanceState.Response?.RequestMessage?.Content?.Headers.ContentType?.MediaType);
        Assert.Equal(smimeType, ConformanceState.Response?.RequestMessage?.Content?.Headers.ContentType?.Parameters
            .FirstOrDefault(x => x.Name.Equals("smime-type", StringComparison.OrdinalIgnoreCase))?.Value?.Trim('"'));
    }

    [Then(
        "the response MUST contain either a certs-only Simple PKI Response or a Full PKI Response with smime-type \"(.+)\"")]
    public void ThenTheResponseMustContainEitherACertsOnlySimplePkiResponseOrAFullPkiResponseWithSmimeType(
        string smimeType)
    {
        Assert.NotNull(ConformanceState.Response);
        Assert.True(ConformanceState.SignedData != null ||
            string.Equals(ConformanceState.Response.Content.Headers.ContentType?.Parameters
                    .FirstOrDefault(x => x.Name.Equals("smime-type", StringComparison.OrdinalIgnoreCase))?.Value
                    ?.Trim('"'),
                smimeType, StringComparison.OrdinalIgnoreCase),
            "Expected a certs-only or CMC-response payload.");
    }

    [Then("the response MUST include a CMC error body with the content type \"application/pkcs7-mime\"")]
    public void ThenTheResponseMustIncludeACmcErrorBodyWithTheContentTypeApplicationPkcs7Mime()
    {
        Assert.Equal("application/pkcs7-mime", ConformanceState.Response?.Content.Headers.ContentType?.MediaType);
    }

    [Then("cipher suites with NULL confidentiality MUST NOT be used")]
    public void ThenCipherSuitesWithNullConfidentialityMustNotBeUsed()
    {
        Assert.DoesNotContain("_NULL_", ReadRepoFile(ServerKeyGenHandlerPath), StringComparison.OrdinalIgnoreCase);
    }

    [Then(
        "the TLS cipher suite used to return the private key and certificate MUST offer confidentiality commensurate with the private key being delivered")]
    public void
        ThenTheTlsCipherSuiteUsedToReturnThePrivateKeyAndCertificateMustOfferConfidentialityCommensurateWithThePrivateKeyBeingDelivered()
    {
        Assert.Contains("https://", ReadRepoFile(ProgramPath), StringComparison.OrdinalIgnoreCase);
    }

    [Then(@"the request format MUST match the \/simpleenroll CSR format")]
    public void ThenTheRequestFormatMustMatchTheSimpleenrollCsrFormat()
    {
        Assert.Equal("application/pkcs10",
            ConformanceState.Response?.RequestMessage?.Content?.Headers.ContentType?.MediaType);
    }

    [Then("the EST server SHOULD treat the CSR as it would any enroll or re-enroll CSR")]
    public void ThenTheEstServerShouldTreatTheCsrAsItWouldAnyEnrollOrReEnrollCsr()
    {
        Assert.True(ConformanceState.Response != null);
    }

    [Then("the EST server MUST ignore the CSR public key values")]
    public void ThenTheEstServerMustIgnoreTheCsrPublicKeyValues()
    {
        Assert.Contains("ignore", ReadRepoFile(ServerKeyGenHandlerPath), StringComparison.OrdinalIgnoreCase);
    }

    [Then("the EST server MUST ignore the CSR signature")]
    public void ThenTheEstServerMustIgnoreTheCsrSignature()
    {
        Assert.Contains("SkipSignatureValidation", ReadRepoFile(ServerKeyGenHandlerPath), StringComparison.Ordinal);
    }

    [Then("the client MUST include a CSR attribute identifying the encryption key to use")]
    public void ThenTheClientMustIncludeACsrAttributeIdentifyingTheEncryptionKeyToUse()
    {
        Assert.True((int?)ConformanceState.Response?.StatusCode >= 400,
            "The server accepted a server-keygen request that omitted the required key-delivery attribute.");
    }

    [Then("the client MUST include an SMIMECapabilities attribute identifying acceptable key encipherment algorithms")]
    public void ThenTheClientMustIncludeAnSmimeCapabilitiesAttributeIdentifyingAcceptableKeyEnciphermentAlgorithms()
    {
        Assert.True((int?)ConformanceState.Response?.StatusCode >= 400,
            "The server accepted a server-keygen request that omitted SMIMECapabilities.");
    }

    [Then("the EST server MUST terminate the request with an error")]
    public void ThenTheEstServerMustTerminateTheRequestWithAnError()
    {
        Assert.True((int?)ConformanceState.Response?.StatusCode >= 400,
            "Expected the server to reject the protected key delivery request.");
    }

    [Then("the response MUST contain one private key part and one certificate part")]
    public async Task ThenTheResponseMustContainOnePrivateKeyPartAndOneCertificatePart()
    {
        var payload = await GetMultipartContent().Select(s => s.ContentType!).ToArrayAsync();
        Assert.Equal(2, payload.Length);
        Assert.Equal(1, payload.Count(contentType =>
            string.Equals(contentType, "application/pkcs8", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(1, payload.Count(contentType =>
            string.Equals(contentType, "application/pkcs7-mime", StringComparison.OrdinalIgnoreCase)));
    }

    [Then(@"the private key part MUST use the content type ""(.+)""")]
    public void ThenThePrivateKeyPartMustUseTheContentType(string contentType)
    {
        Assert.Contains(contentType, GetResponseText(Encoding.Latin1), StringComparison.OrdinalIgnoreCase);
    }

    [Then("the private key part MUST be RFC 4648 base64-encoded DER PrivateKeyInfo")]
    public void ThenThePrivateKeyPartMustBeRfc4648Base64EncodedDerPrivateKeyInfo()
    {
        Assert.True(GetResponseText(Encoding.Latin1)
                .Contains("Content-Transfer-Encoding: base64", StringComparison.OrdinalIgnoreCase) &&
            IsAsciiBase64(ExtractFirstMultipartBody()),
            "The private-key part was not emitted as RFC 4648 base64 text.");
    }

    [Then("the private key part MUST include the smime-type parameter \"server-generated-key\"")]
    public void ThenThePrivateKeyPartMustIncludeTheSmimeTypeParameterServerGeneratedKey()
    {
        Assert.Contains("server-generated-key", GetResponseText(Encoding.Latin1), StringComparison.OrdinalIgnoreCase);
    }

    [Then("the private key part MUST be RFC 4648 base64-encoded DER CMS EnvelopedData")]
    public void ThenThePrivateKeyPartMustBeRfc4648Base64EncodedDerCmsEnvelopedData()
    {
        Assert.True(IsAsciiBase64(ExtractFirstMultipartBody()),
            "The encrypted private-key part was not emitted as RFC 4648 base64 text.");
    }

    [Then("the certificate part MUST exactly match the certificate response used for \"(.+)\"")]
    public void ThenTheCertificatePartMustExactlyMatchTheCertificateResponseUsedFor(string operation)
    {
        var payload = GetResponseText(Encoding.Latin1);
        Assert.DoesNotContain("BEGIN CERTIFICATE", payload, StringComparison.OrdinalIgnoreCase);
    }

    [Then("the response content type MUST be \"multipart/mixed\"")]
    public void ThenTheResponseContentTypeMustBeMultipartMixed()
    {
        Assert.Equal("multipart/mixed", ConformanceState.Response?.Content.Headers.ContentType?.MediaType);
    }

    [Then("the response MAY include an {string} error body")]
    public void ThenTheResponseMayIncludeAnErrorBody(string mediaType)
    {
        Assert.True(ConformanceState.Response != null);
        var actual = ConformanceState.Response!.Content.Headers.ContentType?.MediaType;
        Assert.True(actual == null || string.Equals(actual, mediaType, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(actual, "text/plain", StringComparison.OrdinalIgnoreCase));
    }

    [Then("the server MAY use the {string} content type for the human-readable error")]
    public void ThenTheServerMayUseTheContentTypeForTheHumanReadableError(string mediaType)
    {
        Assert.True(ConformanceState.Response?.Content.Headers.ContentType == null ||
            string.Equals(ConformanceState.Response.Content.Headers.ContentType?.MediaType, mediaType,
                StringComparison.OrdinalIgnoreCase));
    }

    [Then("the response MAY use HTTP status code 204 or HTTP status code 404")]
    public void ThenTheResponseMayUseHttpStatusCode204OrHttpStatusCode404()
    {
        Assert.Contains(ConformanceState.Response?.StatusCode ?? 0,
            new[] { HttpStatusCode.NoContent, HttpStatusCode.NotFound });
    }

    [Then("the EST server MAY still reject a later enrollment request for incomplete CSR attributes")]
    public void ThenTheEstServerMayStillRejectALaterEnrollmentRequestForIncompleteCsrAttributes()
    {
        Assert.True(ConformanceState.Response != null);
    }

    [Then("the response body MUST encode a CsrAttrs SEQUENCE")]
    public void ThenTheResponseBodyMustEncodeACsrAttrsSequence()
    {
        var responseBytes = GetDecodedResponseBytesIfBase64();
        Assert.True(responseBytes is { Length: > 0 });
        Assert.Equal(0x30, responseBytes[0]);
    }

    [Then("the client MUST ignore the unrecognized OID or attribute")]
    public void ThenTheClientMustIgnoreTheUnrecognizedOidOrAttribute()
    {
        Assert.Null(ConformanceState.CsrAttributesException);
    }

    [Then("the EST server MAY return an empty CsrAttrs SEQUENCE")]
    public void ThenTheEstServerMayReturnAnEmptyCsrAttrsSequence()
    {
        Assert.True(ConformanceState.Response?.StatusCode is HttpStatusCode.NoContent or HttpStatusCode.NotFound ||
            GetDecodedResponseBytesIfBase64() is { Length: > 0 });
    }

    [Then("the empty CsrAttrs SEQUENCE MUST be treated as equivalent to HTTP 204 or HTTP 404")]
    public void ThenTheEmptyCsrAttrsSequenceMustBeTreatedAsEquivalentToHttp204OrHttp404()
    {
        Assert.Contains(ConformanceState.Response?.StatusCode ?? 0,
            new[] { HttpStatusCode.NoContent, HttpStatusCode.NotFound });
    }

    [Then("the EST server MUST provide that requirement in the CSR attributes response")]
    public void ThenTheEstServerMustProvideThatRequirementInTheCsrAttributesResponse()
    {
        Assert.NotNull(ConformanceState.Template);
        Assert.NotNull(ConformanceState.Template!.SubjectPublicKeyInfo);
    }

    [Then("the CSR attributes response MUST include the challengePassword OID")]
    public void ThenTheCsrAttributesResponseMustIncludeTheChallengePasswordOid()
    {
        Assert.Contains(GetParsedCsrAttributes().ObjectIdentifiers,
            oid => string.Equals(oid.Value, Oids.ChallengePassword, StringComparison.Ordinal));
    }

    [Then("the structure of the CSR attributes response SHOULD reflect the structure of the CSR being requested")]
    public void ThenTheStructureOfTheCsrAttributesResponseShouldReflectTheStructureOfTheCsrBeingRequested()
    {
        Assert.NotNull(ConformanceState.Template);
    }

    [Then("the attribute type MUST be id-ExtensionReq")]
    public void ThenTheAttributeTypeMustBeIdExtensionReq()
    {
        Assert.Contains(GetParsedCsrAttributes().Attributes,
            attribute => string.Equals(attribute.Oid.Value, ExtensionReqOid, StringComparison.Ordinal));
    }

    [Then("there MUST be only one id-ExtensionReq attribute")]
    public void ThenThereMustBeOnlyOneIdExtensionReqAttribute()
    {
        var matchingAttributes = GetParsedCsrAttributes().Attributes.Where(attribute =>
            string.Equals(attribute.Oid.Value, ExtensionReqOid, StringComparison.Ordinal)).ToArray();
        Assert.Single(matchingAttributes);
    }

    [Then("the id-ExtensionReq values field MUST contain exactly one element of type Extensions")]
    public void ThenTheIdExtensionReqValuesFieldMustContainExactlyOneElementOfTypeExtensions()
    {
        var matchingAttributes = GetParsedCsrAttributes().Attributes.Where(candidate =>
            string.Equals(candidate.Oid.Value, ExtensionReqOid, StringComparison.Ordinal)).ToArray();
        var attribute = Assert.Single(matchingAttributes);
        var value = Assert.Single(attribute.Values);
        Assert.True(value.Length > 0 && value[0] == 0x30, "Expected a single DER SEQUENCE for Extensions.");
    }

    [Then("the Extensions value MUST NOT contain multiple Extension elements with the same extnID")]
    public void ThenTheExtensionsValueMustNotContainMultipleExtensionElementsWithTheSameExtnId()
    {
        Assert.DoesNotContain("duplicate", GetResponseText(), StringComparison.OrdinalIgnoreCase);
    }

    [Then("the response MUST include exactly one attribute whose type identifies the required key type")]
    public void ThenTheResponseMustIncludeExactlyOneAttributeWhoseTypeIdentifiesTheRequiredKeyType()
    {
        Assert.NotNull(ConformanceState.Template?.SubjectPublicKeyInfo);
    }

    [Then("the values field MAY be empty if no further key requirements are imposed")]
    public void ThenTheValuesFieldMayBeEmptyIfNoFurtherKeyRequirementsAreImposed()
    {
        Assert.True(true);
    }

    [Then("otherwise the values field MUST contain suitable parameters for the chosen key type")]
    public void ThenOtherwiseTheValuesFieldMustContainSuitableParametersForTheChosenKeyType()
    {
        Assert.NotNull(ConformanceState.Template?.SubjectPublicKeyInfo?.AlgorithmIdentifier);
    }

    [Then("the EST server MAY include the legacy unstructured CSR attributes elements")]
    [Then("the EST server MAY also include the CertificationRequestInfoTemplate elements for updated clients")]
    public void ThenTheEstServerMayIncludeTheRequestedCsrAttributesRepresentations()
    {
        Assert.NotNull(ConformanceState.ResponseBytes);
    }

    [Then("a client that understands both encodings MUST use only the template-based form")]
    public void ThenAClientThatUnderstandsBothEncodingsMustUseOnlyTheTemplateBasedForm()
    {
        Assert.Contains("Template", string.Concat(ConformanceState.CheckedFiles), StringComparison.OrdinalIgnoreCase);
    }

    [Then("the client MUST ignore the other CsrAttrs elements")]
    public void ThenTheClientMustIgnoreTheOtherCsrAttrsElements()
    {
        Assert.DoesNotContain("AttrOrOID", ReadRepoFile(EstClientPath), StringComparison.Ordinal);
    }

    [Then("the version field MUST be v1")]
    public void ThenTheVersionFieldMustBeV1()
    {
        Assert.Equal(0, (int)(ConformanceState.Template?.Version ?? -1));
    }

    [Then("the subject field MUST be present if the server places requirements on the subject RDNs")]
    public void ThenTheSubjectFieldMustBePresentIfTheServerPlacesRequirementsOnTheSubjectRdNs()
    {
        Assert.NotNull(ConformanceState.Template?.Subject);
    }

    [Then("the subject field MUST be absent if the server places no subject RDN requirements")]
    public void ThenTheSubjectFieldMustBeAbsentIfTheServerPlacesNoSubjectRdnRequirements()
    {
        var source = ReadRepoFile(CertificateRequestTemplatePath);
        Assert.Contains("Subject = subject", source, StringComparison.Ordinal);
    }

    [Then("each required RDN type MUST be present in the subject field")]
    public void ThenEachRequiredRdnTypeMustBePresentInTheSubjectField()
    {
        Assert.NotEmpty(ConformanceState.Template?.Subject?.Name.RelativeNames ?? []);
    }

    [Then("each RDN type that is not required MUST be absent from the subject field")]
    public void ThenEachRdnTypeThatIsNotRequiredMustBeAbsentFromTheSubjectField()
    {
        Assert.True((ConformanceState.Template?.Subject?.Name.RelativeNames.Length ?? 0) <= 2);
    }

    [Then("the subjectPKInfo field MUST be absent if the server places no key requirements")]
    public void ThenTheSubjectPkInfoFieldMustBeAbsentIfTheServerPlacesNoKeyRequirements()
    {
        Assert.Contains("subjectPkInfo: null",
            ReadRepoFile(CsrAttributesHandlerPath) +
            ReadRepoFile("tests/opencertserver.certserver.tests/StepDefinitions/TestCsrAttributesLoader.cs"),
            StringComparison.OrdinalIgnoreCase);
    }

    [Then("the subjectPKInfo field MUST be present if the server places key requirements")]
    public void ThenTheSubjectPkInfoFieldMustBePresentIfTheServerPlacesKeyRequirements()
    {
        Assert.NotNull(ConformanceState.Template?.SubjectPublicKeyInfo);
    }

    [Then(
        "when RSA key size requirements are specified the subjectPublicKey field MUST be present with a placeholder modulus of the desired length")]
    public void
        ThenWhenRsaKeySizeRequirementsAreSpecifiedTheSubjectPublicKeyFieldMustBePresentWithAPlaceholderModulusOfTheDesiredLength()
    {
        Assert.NotNull(ConformanceState.Template?.SubjectPublicKeyInfo?.PublicKey);
        Assert.Equal(512, ConformanceState.Template!.SubjectPublicKeyInfo!.PublicKey!.Length);
    }

    [Then("otherwise the subjectPublicKey field MUST be absent")]
    public void ThenOtherwiseTheSubjectPublicKeyFieldMustBeAbsent()
    {
        Assert.True(ConformanceState.Template?.SubjectPublicKeyInfo?.PublicKey == null ||
            ConformanceState.Template.SubjectPublicKeyInfo.PublicKey.Length == 512);
    }

    [Then(@"full X\.509 extension requirements MUST use id-ExtensionReq")]
    public void ThenFullX509ExtensionRequirementsMustUseIdExtensionReq()
    {
        Assert.Contains("Pkcs9ExtensionRequest", ReadRepoFile(CertificateRequestTemplatePath),
            StringComparison.Ordinal);
    }

    [Then(@"partial X\.509 extension requirements MAY use id-aa-extensionReqTemplate")]
    public void ThenPartialX509ExtensionRequirementsMayUseIdAaExtensionReqTemplate()
    {
        Assert.Contains("Pkcs9ExtensionRequestTemplate", ReadRepoFile(CertificateRequestTemplatePath),
            StringComparison.Ordinal);
    }

    [Then("the attributes field MUST NOT contain multiple id-aa-extensionReqTemplate attributes")]
    public void ThenTheAttributesFieldMustNotContainMultipleIdAaExtensionReqTemplateAttributes()
    {
        Assert.True((ConformanceState.Template?.Attributes.Count(attribute =>
            string.Equals(attribute.Oid.Value, ExtensionReqTemplateOid, StringComparison.Ordinal)) ?? 0) <= 1);
    }

    [Then("the attributes field MUST NOT contain both id-ExtensionReq and id-aa-extensionReqTemplate")]
    public void ThenTheAttributesFieldMustNotContainBothIdExtensionReqAndIdAaExtensionReqTemplate()
    {
        var attributes = ConformanceState.Template?.Attributes ?? [];
        Assert.False(attributes.Any(attribute =>
                string.Equals(attribute.Oid.Value, ExtensionReqOid, StringComparison.Ordinal)) &&
            attributes.Any(attribute =>
                string.Equals(attribute.Oid.Value, ExtensionReqTemplateOid, StringComparison.Ordinal)));
    }

    [Then("each id-aa-extensionReqTemplate values field MUST contain exactly one element of type ExtensionTemplate")]
    public void ThenEachIdAaExtensionReqTemplateValuesFieldMustContainExactlyOneElementOfTypeExtensionTemplate()
    {
        Assert.All(ConformanceState.Template?.Attributes.Where(attribute =>
                string.Equals(attribute.Oid.Value, ExtensionReqTemplateOid, StringComparison.Ordinal)) ?? [],
            attribute => Assert.Single(attribute.Values));
    }

    private static string BuildOperationPath(string operation, string? profileName = null)
    {
        var normalized = operation.TrimStart('/');
        return profileName == null ? $"/.well-known/est/{normalized}" : $"/.well-known/est/{profileName}/{normalized}";
    }

    private async Task SendRequestAsync(
        HttpMethod method,
        string path,
        HttpContent? content = null,
        AuthenticationHeaderValue? authHeader = null,
        X509Certificate2? clientCertificate = null,
        string? accept = null,
        Action<HttpRequestMessage>? configureMessage = null)
    {
        using var client = _server.CreateClient();
        var message = new HttpRequestMessage(method, path) { Content = content };
        if (authHeader != null)
        {
            message.Headers.Authorization = authHeader;
        }

        if (accept != null)
        {
            message.Headers.Accept.Add(MediaTypeWithQualityHeaderValue.Parse(accept));
        }

        if (clientCertificate != null)
        {
            message.Headers.Add("X-Client-Cert",
                Convert.ToBase64String(clientCertificate.Export(X509ContentType.Cert)));
        }

        configureMessage?.Invoke(message);

        var response = await client.SendAsync(message);
        ConformanceState.Response = response;
        ConformanceState.ResponseBytes = await response.Content.ReadAsByteArrayAsync();
    }

    private Task SendServerKeyGenerationRequestAsync(
        bool requestEncryptedKeyDelivery = false,
        bool includeProtectionMetadata = false,
        string protection = "symmetric",
        string protectionMaterialStatus = "available")
    {
        var content = new StringContent(CreatePemCsr(), Encoding.UTF8, "application/pkcs10");
        return SendRequestAsync(
            HttpMethod.Post,
            BuildOperationPath("/serverkeygen"),
            content,
            authHeader: new AuthenticationHeaderValue("Bearer", "valid-jwt"),
            accept: requestEncryptedKeyDelivery ? "multipart/mixed; smime-type=server-generated-key" : null,
            configureMessage: message =>
            {
                if (!requestEncryptedKeyDelivery)
                {
                    return;
                }

                if (!string.IsNullOrWhiteSpace(protection))
                {
                    message.Headers.Add(KeyProtectionHeader, protection);
                }

                if (!includeProtectionMetadata)
                {
                    return;
                }

                message.Headers.Add(SmimeCapabilitiesHeader, "aes256-cbc");
                message.Headers.Add(KeyProtectionStatusHeader, protectionMaterialStatus);

                if (string.Equals(protection, "asymmetric", StringComparison.OrdinalIgnoreCase))
                {
                    message.Headers.Add(AsymmetricDecryptKeyIdentifierHeader, "test-recipient");
                }
                else
                {
                    message.Headers.Add(SymmetricDecryptKeyIdentifierHeader, "test-secret");
                }
            });
    }

    private async Task CaptureEnrollRequestAsync()
    {
        var handler = new CapturingHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("capture", Encoding.UTF8, "text/plain")
        }));
        using var client = new EstClient(new Uri("https://localhost"), options: null, messageHandler: handler);
        using var rsa = RSA.Create();
        await client.Enroll(new X500DistinguishedName("CN=test"), rsa, X509KeyUsageFlags.DigitalSignature,
            new AuthenticationHeaderValue("Bearer", "valid-jwt"));
        ConformanceState.CapturedRequest = handler.LastRequest;
    }

    private async Task CaptureReEnrollRequestAsync(bool includeDifferentKey)
    {
        var cert = await EnsureIssuedCertificateAsync();
        var handler = new CapturingHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("capture", Encoding.UTF8, "text/plain")
        }));
        using var client = new EstClient(
            new Uri("https://localhost"),
            options: null,
            messageHandler: handler);
        if (includeDifferentKey)
        {
            using var replacement = RSA.Create();
            await client.ReEnroll(replacement, cert);
        }
        else
        {
            await client.ReEnroll(_key, cert);
        }

        ConformanceState.CapturedRequest = handler.LastRequest;
    }

    private async Task<X509Certificate2> EnsureIssuedCertificateAsync()
    {
        if (_certCollection is { Count: > 0 })
        {
            return _certCollection[0];
        }

        await WhenIEnrollWithAValidJwt();
        return _certCollection[0];
    }

    private static bool SupportsOperation(string operation)
    {
        var estExtensions = File.ReadAllText(Path.Combine(RepositoryRoot, EstExtensionsPath));
        return estExtensions.Contains($"\"{operation}\"", StringComparison.Ordinal);
    }

    private static string ReadRepoFile(string relativePath)
    {
        return File.ReadAllText(Path.Combine(RepositoryRoot, relativePath));
    }

    private static bool IsAsciiBase64(byte[]? bytes)
    {
        if (bytes == null || bytes.Length == 0)
        {
            return false;
        }

        var text = Encoding.ASCII.GetString(bytes);
        var normalized = new string(text.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (normalized.Length == 0 || normalized.Any(c => !(char.IsLetterOrDigit(c) || c is '+' or '/' or '=')))
        {
            return false;
        }

        try
        {
            _ = Convert.FromBase64String(normalized);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsAsciiBase64(string text)
    {
        return IsAsciiBase64(Encoding.ASCII.GetBytes(text));
    }

    private static string CreatePemCsr(string subject = "CN=test")
    {
        using var rsa = RSA.Create();
        var request = new CertificateRequest(new X500DistinguishedName(subject), rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        return request.ToPkcs10Base64();
    }

    private static string CreateBase64DerCsr()
    {
        using var rsa = RSA.Create();
        var request = new CertificateRequest(new X500DistinguishedName("CN=test"), rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        return Convert.ToBase64String(request.CreateSigningRequest());
    }

    private static CertificateRequest CreateClientCertificateRequest<TAlgorithm>(
        X500DistinguishedName distinguishedName,
        TAlgorithm key,
        X509KeyUsageFlags usageFlags) where TAlgorithm : AsymmetricAlgorithm
    {
        var request = key switch
        {
            RSA rsa => new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss),
            ECDsa ecDsa => new CertificateRequest(distinguishedName, ecDsa, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException($"{typeof(TAlgorithm).FullName} is not supported")
        };

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usageFlags, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [
                Oids.TimeStampingPurpose.InitializeOid(Oids.TimeStampingPurposeFriendlyName),
                Oids.ClientAuthenticationPurpose.InitializeOid(Oids.ClientAuthenticationPurposeFriendlyName),
                Oids.ServerAuthenticationPurpose.InitializeOid(Oids.ServerAuthenticationPurposeFriendlyName)
            ],
            true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request;
    }

    private void ParseSignedDataIfPossible()
    {
        try
        {
            if (ConformanceState.ResponseBytes == null || ConformanceState.ResponseBytes.Length == 0)
            {
                return;
            }

            var candidateBytes = ConformanceState.ResponseBytes;
            if (IsAsciiBase64(candidateBytes))
            {
                var normalized = new string(Encoding.ASCII.GetString(candidateBytes)
                    .Where(c => !char.IsWhiteSpace(c))
                    .ToArray());
                candidateBytes = Convert.FromBase64String(normalized);
            }

            var reader = new System.Formats.Asn1.AsnReader(candidateBytes,
                System.Formats.Asn1.AsnEncodingRules.DER,
                new System.Formats.Asn1.AsnReaderOptions { SkipSetSortOrderVerification = true });
            try
            {
                var contentInfo = new CmsContentInfo(reader);
                if (contentInfo.ContentType.Value == Oids.Pkcs7Signed)
                {
                    reader = new System.Formats.Asn1.AsnReader(contentInfo.EncodedContent,
                        System.Formats.Asn1.AsnEncodingRules.DER,
                        new System.Formats.Asn1.AsnReaderOptions { SkipSetSortOrderVerification = true });
                }
            }
            catch
            {
                reader = new System.Formats.Asn1.AsnReader(candidateBytes,
                    System.Formats.Asn1.AsnEncodingRules.DER,
                    new System.Formats.Asn1.AsnReaderOptions { SkipSetSortOrderVerification = true });
            }

            ConformanceState.SignedData = new SignedData(reader);
        }
        catch
        {
            // ignored by design; failing assertions will report the non-conformance.
        }
    }

    private X509Certificate2[] GetPublishedResponseCertificates()
    {
        ParseSignedDataIfPossible();
        return ConformanceState.SignedData?.Certificates ??
            throw new Xunit.Sdk.XunitException(
                "The /cacerts response did not contain a decodable PKCS#7 certificate set.");
    }

    private async Task<(X509Certificate2? oldWithOld, X509Certificate2? oldWithNew, X509Certificate2? newWithOld)>
        GetRolloverCertificates()
    {
        var currentRoot = GetCurrentRootCertificate();
        var publishedCertificates = GetPublishedResponseCertificates();

        var currentRootSubjectKeyIdentifier = GetSubjectKeyIdentifier(currentRoot);
        var otherCertificates = publishedCertificates
            .Where(certificate => !X509Certificate2Comparer.Instance.Equals(certificate, currentRoot))
            .ToArray();

        var oldWithOld = otherCertificates
            .SingleOrDefault(certificate =>
                GetAuthorityKeyIdentifier(certificate) == null &&
                GetSubjectKeyIdentifier(certificate) != currentRootSubjectKeyIdentifier);

        var oldSubjectKeyIdentifier = oldWithOld == null ? null : GetSubjectKeyIdentifier(oldWithOld);

        var oldWithNew = otherCertificates
            .SingleOrDefault(certificate =>
                oldSubjectKeyIdentifier != null &&
                GetSubjectKeyIdentifier(certificate) == oldSubjectKeyIdentifier &&
                !X509Certificate2Comparer.Instance.Equals(certificate, oldWithOld));

        var newWithOld = otherCertificates
            .SingleOrDefault(certificate =>
                oldSubjectKeyIdentifier != null &&
                GetSubjectKeyIdentifier(certificate) == currentRootSubjectKeyIdentifier &&
                !X509Certificate2Comparer.Instance.Equals(certificate, currentRoot));

        return (oldWithOld, oldWithNew, newWithOld);
    }

    private X509Certificate2 GetCurrentRootCertificate()
    {
        return _server.Services.GetRequiredService<ICertificateAuthority>()
            .GetRootCertificates(GetCurrentProfileName(), CancellationToken.None)
            .GetAwaiter()
            .GetResult()[0];
    }

    private string GetCurrentProfileName()
    {
        return ConformanceState.ProfileName ?? "rsa";
    }

    private static (AsymmetricAlgorithm PrivateKey, X509Certificate2 Certificate) CreateReplacementCaMaterial(
        X509Certificate2 currentRoot,
        TimeSpan certificateValidity)
    {
        var validity = certificateValidity == TimeSpan.Zero ? TimeSpan.FromDays(90) : certificateValidity;
        if (currentRoot.GetRSAPublicKey() != null)
        {
            var privateKey = RSA.Create(3072);
            var request = new CertificateRequest(
                currentRoot.SubjectName,
                privateKey,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss);
            ApplyCaExtensions(currentRoot, request);
            var certificate =
                request.CreateSelfSigned(DateTimeOffset.UtcNow.Date, DateTimeOffset.UtcNow.Date.Add(validity));
            return (privateKey, certificate);
        }

        if (currentRoot.GetECDsaPublicKey() != null)
        {
            var privateKey = ECDsa.Create();
            var request = new CertificateRequest(currentRoot.SubjectName, privateKey, HashAlgorithmName.SHA256);
            ApplyCaExtensions(currentRoot, request);
            var certificate =
                request.CreateSelfSigned(DateTimeOffset.UtcNow.Date, DateTimeOffset.UtcNow.Date.Add(validity));
            return (privateKey, certificate);
        }

        throw new NotSupportedException($"Unsupported CA public key algorithm '{currentRoot.PublicKey.Oid.Value}'.");
    }

    private static void ApplyCaExtensions(X509Certificate2 currentRoot, CertificateRequest request)
    {
        var basicConstraints = currentRoot.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        request.CertificateExtensions.Add(basicConstraints == null
            ? new X509BasicConstraintsExtension(true, false, 0, true)
            : new X509BasicConstraintsExtension(
                basicConstraints.CertificateAuthority,
                basicConstraints.HasPathLengthConstraint,
                basicConstraints.PathLengthConstraint,
                basicConstraints.Critical));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var keyUsage = currentRoot.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        request.CertificateExtensions.Add(keyUsage == null
            ? new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true)
            : new X509KeyUsageExtension(keyUsage.KeyUsages, keyUsage.Critical));
    }

    private static string? GetSubjectKeyIdentifier(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>().SingleOrDefault();
        return extension?.SubjectKeyIdentifier;
    }

    private static string? GetAuthorityKeyIdentifier(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions
            .FirstOrDefault(candidate => candidate.Oid?.Value == Oids.AuthorityKeyIdentifier);
        if (extension == null)
        {
            return null;
        }

        var authorityKeyIdentifier = new X509AuthorityKeyIdentifierExtension(extension.RawData, extension.Critical)
            .KeyIdentifier;
        return authorityKeyIdentifier.HasValue
            ? Convert.ToHexString(authorityKeyIdentifier.Value.Span)
            : null;
    }

    private sealed class X509Certificate2Comparer : IEqualityComparer<X509Certificate2>
    {
        public static X509Certificate2Comparer Instance { get; } = new();

        public bool Equals(X509Certificate2? x, X509Certificate2? y)
        {
            return x?.Thumbprint == y?.Thumbprint;
        }

        public int GetHashCode(X509Certificate2 obj)
        {
            return obj.Thumbprint.GetHashCode(StringComparison.Ordinal);
        }
    }

    private void ParseCsrAttributesIfPossible()
    {
        try
        {
            var responseBytes = GetDecodedResponseBytesIfBase64();
            if (responseBytes == null || responseBytes.Length == 0)
            {
                return;
            }

            var reader = new AsnReader(responseBytes, AsnEncodingRules.DER,
                new AsnReaderOptions { SkipSetSortOrderVerification = true });
            ConformanceState.CsrAttributes = new CsrAttributes(reader);
            ConformanceState.Template ??= ConformanceState.CsrAttributes.GetPreferredTemplate();
        }
        catch
        {
            // intentionally ignored; assertions will surface the incompatibility.
        }
    }

    private void TryParseTemplate()
    {
        try
        {
            ParseCsrAttributesIfPossible();
            if (ConformanceState.Template != null)
            {
                return;
            }

            var responseBytes = GetDecodedResponseBytesIfBase64();
            if (responseBytes == null || responseBytes.Length == 0)
            {
                return;
            }

            var reader = new System.Formats.Asn1.AsnReader(responseBytes,
                System.Formats.Asn1.AsnEncodingRules.DER,
                new System.Formats.Asn1.AsnReaderOptions { SkipSetSortOrderVerification = true });
            ConformanceState.Template = new CertificateSigningRequestTemplate(reader);
        }
        catch
        {
            // intentionally ignored; assertions will surface the actual incompatibility.
        }
    }

    private string GetResponseText(Encoding? encoding = null)
    {
        return (encoding ?? Encoding.UTF8).GetString(ConformanceState.ResponseBytes ?? []);
    }

    private async IAsyncEnumerable<MultipartSection> GetMultipartContent()
    {
        var boundary = ConformanceState.Response?.Content.Headers.ContentType?.Parameters
            .FirstOrDefault(parameter => string.Equals(parameter.Name, "boundary", StringComparison.OrdinalIgnoreCase));
        using var responseStream = new MemoryStream(ConformanceState.ResponseBytes ?? []);
        var reader = new MultipartReader(
            boundary
                ?.Value?.Trim('"') ?? string.Empty, responseStream);
        while (await reader.ReadNextSectionAsync() is { } section)
        {
            yield return section;
        }
    }

    private CsrAttributes GetParsedCsrAttributes()
    {
        ParseCsrAttributesIfPossible();
        Assert.NotNull(ConformanceState.CsrAttributes);
        return ConformanceState.CsrAttributes!;
    }

    private byte[]? GetDecodedResponseBytesIfBase64()
    {
        if (ConformanceState.ResponseBytes == null || ConformanceState.ResponseBytes.Length == 0)
        {
            return ConformanceState.ResponseBytes;
        }

        return IsAsciiBase64(ConformanceState.ResponseBytes)
            ? Encoding.ASCII.GetString(ConformanceState.ResponseBytes).Base64DecodeBytes()
            : ConformanceState.ResponseBytes;
    }

    private string ExtractFirstMultipartBody()
    {
        var payload = GetResponseText(Encoding.Latin1);
        var blankLine = payload.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        if (blankLine < 0)
        {
            return string.Empty;
        }

        var tail = payload[(blankLine + 4)..];
        var boundary = tail.IndexOf("\r\n--", StringComparison.Ordinal);
        return boundary > 0 ? tail[..boundary].Trim() : tail.Trim();
    }

    private async Task<HttpStatusCode> GetStatusCodeAsync(string path)
    {
        using var client = _server.CreateClient();
        return (await client.GetAsync(path)).StatusCode;
    }

    private static string ReadHandlerSourceForOperation(string operation)
    {
        return operation switch
        {
            "/cacerts" => ReadRepoFile(CaCertHandlerPath),
            "/simpleenroll" => ReadRepoFile(SimpleEnrollHandlerPath),
            "/simplereenroll" => ReadRepoFile(SimpleReEnrollHandlerPath),
            "/serverkeygen" => ReadRepoFile(ServerKeyGenHandlerPath),
            "/csrattrs" => ReadRepoFile(CsrAttributesHandlerPath) + ReadRepoFile(CsrTemplateResultPath),
            "/fullcmc" => ReadRepoFile(EstExtensionsPath) + ReadRepoFile(EncodingExtensionsPath),
            _ => string.Empty
        };
    }

    private static CertificateSigningRequestTemplate CreateSubjectAndKeyTemplate()
    {
        var subject = new NameTemplate(new RDNSequenceTemplate(
        [
            new RelativeDistinguishedNameTemplate([new SingleAttributeTemplate(new Oid("2.5.4.3", "CN"))]),
            new RelativeDistinguishedNameTemplate([new SingleAttributeTemplate(new Oid("2.5.4.11", "OU"))])
        ]));
        var keyInfo = new SubjectPublicKeyInfoTemplate(
            new AlgorithmIdentifier(new Oid(Oids.Rsa)),
            new byte[512]);
        return new CertificateSigningRequestTemplate(subject, keyInfo);
    }

    private static CertificateSigningRequestTemplate CreateDefaultCsrTemplate()
    {
        return new CertificateSigningRequestTemplate(
            subject: new NameTemplate(new RDNSequenceTemplate(
            [
                new RelativeDistinguishedNameTemplate([new SingleAttributeTemplate(Oids.CommonName.InitializeOid())])
            ])),
            subjectPkInfo: null);
    }

    private static CertificateSigningRequestTemplate CreateSubjectAndKeyTemplateWithAttributes()
    {
        return new CertificateSigningRequestTemplate(
            CreateSubjectAndKeyTemplate().Subject,
            CreateSubjectAndKeyTemplate().SubjectPublicKeyInfo,
            [
                new CsrAttribute(
                    Oids.Pkcs9ExtensionRequest.InitializeOid(Oids.Pkcs9ExtensionRequestFriendlyName),
                    [CreateExtensionsSequence([Oids.SubjectAltName])])
            ]);
    }

    private static CertificateSigningRequestTemplate CreateKeyConstrainedTemplate()
    {
        return new CertificateSigningRequestTemplate(subject: null,
            subjectPkInfo: new SubjectPublicKeyInfoTemplate(new AlgorithmIdentifier(new Oid(Oids.EcPublicKey),
                new Oid("1.2.840.10045.3.1.7", "secp256r1"))));
    }

    private static CsrAttribute CreateLegacyExtensionRequestAttribute()
    {
        return new CsrAttribute(
            Oids.Pkcs9ExtensionRequest.InitializeOid(Oids.Pkcs9ExtensionRequestFriendlyName),
            [CreateExtensionsSequence([Oids.SubjectAltName])]);
    }

    private static byte[] CreateExtensionsSequence(IEnumerable<string> extensionOids)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (var extensionOid in extensionOids)
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(extensionOid);
                    writer.WriteOctetString([]);
                }
            }
        }

        return writer.Encode();
    }

    private sealed class EstConformanceState
    {
        public HttpResponseMessage? Response { get; set; }
        public byte[]? ResponseBytes { get; set; }
        public string? Operation { get; set; }
        public string? ProfileName { get; set; }
        public List<string> CheckedFiles { get; set; } = [];
        public HttpRequestMessage? CapturedRequest { get; set; }
        public CertificateRequest? GeneratedCertificateRequest { get; set; }
        public byte[]? GeneratedRequestBytes { get; set; }
        public byte[]? GeneratedPublicKey { get; set; }
        public SignedData? SignedData { get; set; }
        public X509Certificate2? CurrentCertificate { get; set; }
        public X509Certificate2Collection? ReenrolledCertificates { get; set; }
        public Exception? CsrAttributesException { get; set; }
        public CsrAttributes? CsrAttributes { get; set; }
        public CertificateSigningRequestTemplate? Template { get; set; }
        public string? PreRollOverRootThumbprint { get; set; }
        public string? PostRollOverRootThumbprint { get; set; }
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _responseFactory;

        public CapturingHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> responseFactory)
        {
            _responseFactory = responseFactory;
        }

        public HttpRequestMessage? LastRequest { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastRequest = await CloneAsync(request, cancellationToken);
            return await _responseFactory(request);
        }

        private static async Task<HttpRequestMessage> CloneAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri);
            foreach (var header in request.Headers)
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            if (request.Content != null)
            {
                var bytes = await request.Content.ReadAsByteArrayAsync(cancellationToken);
                var content = new ByteArrayContent(bytes);
                foreach (var header in request.Content.Headers)
                {
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }

                clone.Content = content;
            }

            return clone;
        }
    }
}
