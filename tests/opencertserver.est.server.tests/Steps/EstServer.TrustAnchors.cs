namespace OpenCertServer.Est.Tests.Steps;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Est.Client;
using Reqnroll;
using Xunit;

public partial class EstServer
{
    [Given("an EST server configured with an external client trust anchor")]
    public async Task GivenAnEstServerConfiguredWithAnExternalClientTrustAnchor()
    {
        var root = CreateExternalClientTrustAnchor();
        _context["externalClientTrustAnchor"] = root;
        var anchors = new X509Certificate2Collection { root };
        _context["estTrustAnchors"] = anchors;

        await GivenACertificateServerThatCompliesWithEstRfc().ConfigureAwait(false);
    }

    [Given("an EST server without the external client trust anchor")]
    public async Task GivenAnEstServerWithoutTheExternalClientTrustAnchor()
    {
        _context["externalClientTrustAnchor"] = CreateExternalClientTrustAnchor();
        await GivenACertificateServerThatCompliesWithEstRfc().ConfigureAwait(false);
    }

    [When("a client certificate from the external CA enrolls")]
    public Task WhenAClientCertificateFromTheExternalCaEnrolls() =>
        WhenAClientCertificateFromTheExternalCaEnrollsInProfile("rsa");

    [When("a client certificate from the external CA enrolls in profile {string}")]
    public async Task WhenAClientCertificateFromTheExternalCaEnrollsInProfile(string profileName)
    {
        var root = _context.TryGetValue("externalClientIssuer", out var issuer)
            ? Assert.IsType<X509Certificate2>(issuer)
            : Assert.IsType<X509Certificate2>(_context["externalClientTrustAnchor"]);
        using var clientKey = RSA.Create();
        var request = new CertificateRequest(
            "CN=test",
            clientKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.2") },
            critical: false));

        using var issuerKey = root.GetRSAPrivateKey()!;
        var signatureGenerator = X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);
        using var clientCertificate = request.Create(
            root.SubjectName,
            signatureGenerator,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(30),
            CreateSerialNumber()).CopyWithPrivateKey(clientKey);

        _context["externalClientCertificate"] = X509CertificateLoader.LoadCertificate(clientCertificate.RawData);
        var (error, certificates) = await SubmitSimpleEnrollAsync(request, profileName, clientCertificate)
            .ConfigureAwait(false);
        _context["errorMessage"] = error;
        _context["enrolledCertificate"] = certificates;
    }

    [Given("an EST server with an external client trust anchor only in the rsa profile")]
    public async Task GivenAProfileTrustAnchor()
    {
        var root = CreateExternalClientTrustAnchor();
        _context["externalClientTrustAnchor"] = root;
        _context["profileTrustAnchors"] = new X509Certificate2Collection(root);
        await GivenACertificateServerThatCompliesWithEstRfc().ConfigureAwait(false);
    }

    [Given("an EST server with an external client intermediate and {string} trust")]
    public async Task GivenAnExternalClientIntermediate(string trust)
    {
        var root = CreateExternalClientTrustAnchor();
        using var key = RSA.Create();
        var request = new CertificateRequest("CN=External EST Intermediate", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var publicCertificate = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(90), CreateSerialNumber());
        var intermediate = publicCertificate.CopyWithPrivateKey(key);
        _context["externalClientTrustAnchor"] = root;
        _context["externalClientIssuer"] = intermediate;
        var commonChain = trust is "server-wide" or "shared intermediate";
        var commonRoot = trust is "server-wide" or "shared root";
        var chainCertificates =
            new X509Certificate2Collection(X509CertificateLoader.LoadCertificate(intermediate.RawData));
        if (trust == "no root")
        {
            chainCertificates.Add(X509CertificateLoader.LoadCertificate(root.RawData));
        }

        _context[commonChain ? "estChainCertificates" : "profileChainCertificates"] = chainCertificates;
        if (trust != "no root")
        {
            _context[commonRoot ? "estTrustAnchors" : "profileTrustAnchors"] =
                new X509Certificate2Collection(root);
        }

        await GivenACertificateServerThatCompliesWithEstRfc().ConfigureAwait(false);
    }

    [When("the default profile is requested by the external client")]
    public async Task WhenTheDefaultProfileIsRequested()
    {
        var certificate = Assert.IsType<X509Certificate2>(_context["externalClientCertificate"]);
        using var handler = new TestMessageHandler(_server, certificate);
        using var client = new HttpClient(handler);
        using var key = RSA.Create();
        var request = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var content = new StringContent(request.CreateSigningRequestPem(), System.Text.Encoding.UTF8,
            "application/pkcs10");
        using var response = await client.PostAsync("https://localhost/.well-known/est/simpleenroll", content)
            .ConfigureAwait(false);
        Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync().ConfigureAwait(false));
    }

    [Then("cacerts publishes the issuing chain but not the external client trust anchor for profile {string}")]
    public async Task ThenCacertsPublishesOnlyIssuingTrust(string profileName)
    {
        using var handler = new TestMessageHandler(_server);
        var client = new EstClient(new Uri("https://localhost"), options: null,
            profileName: profileName, messageHandler: handler);
        var published = await client.ServerCertificates().ConfigureAwait(false);
        var profile = await _server.Services.GetRequiredService<IStoreCaProfiles>().GetProfile(profileName)
            .ConfigureAwait(false);
        foreach (var certificate in profile.CertificateChain)
        {
            Assert.Contains(published, item => item.Thumbprint == certificate.Thumbprint);
        }

        var external = Assert.IsType<X509Certificate2>(_context["externalClientTrustAnchor"]);
        Assert.DoesNotContain(published, item => item.Thumbprint == external.Thumbprint);
    }

    [When("the external client certificate accesses a non-EST route")]
    public async Task WhenTheExternalClientCertificateAccessesANonEstRoute()
    {
        var certificate = Assert.IsType<X509Certificate2>(_context["externalClientCertificate"]);
        var responseContext = await _server.SendAsync(context =>
        {
            context.Request.Method = HttpMethod.Get.Method;
            context.Request.Scheme = "https";
            context.Request.Path = "/non-est-probe";
            context.Connection.ClientCertificate = certificate;
        }).ConfigureAwait(false);

        using var reader = new StreamReader(responseContext.Response.Body);
        _context["nonEstAuthenticationResult"] = await reader.ReadToEndAsync().ConfigureAwait(false);
    }

    [Then("the enrollment is refused")]
    public void ThenTheEnrollmentIsRefused()
    {
        Assert.NotNull(_context["errorMessage"]);
        Assert.Null(_context["enrolledCertificate"]);
    }

    [Then("the client is not authenticated on the non-EST route")]
    public void ThenTheClientIsNotAuthenticatedOnTheNonEstRoute()
    {
        Assert.Equal("unauthenticated", _context["nonEstAuthenticationResult"]);
    }

    private static X509Certificate2 CreateExternalClientTrustAnchor()
    {
        using var key = RSA.Create();
        var request = new CertificateRequest(
            "CN=External EST Client Root",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 1, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
            critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static byte[] CreateSerialNumber()
    {
        var serialNumber = RandomNumberGenerator.GetBytes(16);
        serialNumber[0] &= 0x7F;
        serialNumber[0] |= 0x01;
        return serialNumber;
    }
}
