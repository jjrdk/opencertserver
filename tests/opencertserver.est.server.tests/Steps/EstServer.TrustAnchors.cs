namespace OpenCertServer.Est.Tests.Steps;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
    public async Task WhenAClientCertificateFromTheExternalCaEnrolls()
    {
        var root = Assert.IsType<X509Certificate2>(_context["externalClientTrustAnchor"]);
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

        var (error, certificates) = await SubmitSimpleEnrollAsync(request, "rsa", clientCertificate)
            .ConfigureAwait(false);
        _context["errorMessage"] = error;
        _context["enrolledCertificate"] = certificates;
    }

    [When("the external client certificate accesses a non-EST route")]
    public async Task WhenTheExternalClientCertificateAccessesANonEstRoute()
    {
        var certificate = Assert.IsType<X509Certificate2>(_context["externalClientTrustAnchor"]);
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
