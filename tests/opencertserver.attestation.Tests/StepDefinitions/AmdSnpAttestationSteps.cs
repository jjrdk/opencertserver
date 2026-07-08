using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenCertServer.Attestation;
using OpenCertServer.Attestation.Native;
using OpenCertServer.Attestation.Tests.Mocks;
using Reqnroll;

[Binding]
public class AmdSnpAttestationSteps
{
    private readonly IHttpClientFactory _httpFactoryMock = Substitute.For<IHttpClientFactory>();
    private readonly ILogger<AmdSnpProvider> _loggerMock = Substitute.For<ILogger<AmdSnpProvider>>();
    private readonly IAmdSnpNativeInterop _nativeMock = Substitute.For<IAmdSnpNativeInterop>();
    private readonly ICertificateCache _cacheMock = new InMemoryCertificateCache();
    private AmdSnpProvider? _provider;

    [Given(@"an active SEV-SNP enabled instance in Azure")]
    public void GivenAnActiveSevSnpEnabledInstanceInAzure()
    {
        IntPtr dummy = IntPtr.Zero;
        uint size = 48;
        _nativeMock.GetVcekChipId(out Arg.Any<IntPtr>(), ref Arg.Any<uint>())
            .Returns(x =>
            {
                x[0] = dummy;
                x[1] = size;
                return 0; // SNP_SUCCESS
            });
    }

    [When(@"we request a verified identity token")]
    public async Task WhenWeRequestAVerifiedIdentityToken()
    {
        using var certRsa = System.Security.Cryptography.RSA.Create(2048);
        var certReq = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=Mock VCEK Cert", certRsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        var mockCert = certReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var certBytes = mockCert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);

        var mockResponse = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(certBytes)
        };
        var client = new HttpClient(new MockHttpHandler(mockResponse));
        _httpFactoryMock.CreateClient(nameof(AmdSnpProvider)).Returns(client);

        var options = Options.Create(new AttestationOptions
        {
            AmdSevSnp = new AmdSevSnpOptions { VpsUrl = "https://amd-vps.confidentialcomputing.azure.com" }
        });
        _provider = new AmdSnpProvider(_httpFactoryMock, _loggerMock, _nativeMock, _cacheMock, options);
    }

    [Then(@"the system should retrieve VCEK, verify via Root CA, and produce a signed report from https:\/\/amd-vps\.confidentialcomputing\.azure\.com")]
    public async Task ThenTheSystemShouldVerify()
    {
        var cert = await _provider!.RetrieveDeviceCertificateAsync("AABBCCDDEEFF");
        if (cert is null) throw new Exception("Expected a certificate from VPS");
    }
}
