namespace OpenCertServer.Scep.Tests.Steps;

using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Scep.Server;
using Reqnroll;
using Xunit;

[Binding]
public sealed class ScepServer : IDisposable
{
    private const string Challenge = "geheim";
    private const string Subject = "CN=Testgeraet, O=entra-vpn";

    private IHost _host = null!;
    private ScepTestClient _client = null!;
    private X509Certificate2 _rsaCa = null!;
    private X509Certificate2 _ecdsaCa = null!;
    private X509Certificate2 _ra = null!;

    private string? _caps;
    private string _caCertContentType = "";
    private X509Certificate2Collection _caCerts = [];
    private HttpResponseMessage? _response;
    private ScepTestResponse? _certRep;
    private RSA? _clientKey;
    private X509Certificate2? _clientSigner;
    private readonly string _transactionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
    private readonly byte[] _senderNonce = RandomNumberGenerator.GetBytes(16);

    [Given("a certificate server that complies with SCEP \\(RFC 8894\\)")]
    public async Task GivenACertificateServer()
    {
        using var rsaKey = RSA.Create(2048);
        var rsaReq = new CertificateRequest("CN=SCEP Test RSA CA", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rsaReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rsaReq.PublicKey, false));
        rsaReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        _rsaCa = rsaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecReq = new CertificateRequest("CN=SCEP Test ECDSA CA", ecKey, HashAlgorithmName.SHA256);
        ecReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        ecReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(ecReq.PublicKey, false));
        ecReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        _ecdsaCa = ecReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        // The RA: RSA, issued by the RSA CA, for decrypting requests and signing responses.
        var raKey = RSA.Create(2048);
        var raReq = new CertificateRequest("CN=SCEP Test RA", raKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        raReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        _ra = raReq.Create(_rsaCa, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6),
                RandomNumberGenerator.GetBytes(16))
            .CopyWithPrivateKey(raKey);

        var rsaCa = _rsaCa;
        var ecdsaCa = _ecdsaCa;
        var ra = _ra;
        _host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization();
                    services.AddInMemoryCertificateStore()
                        .AddCertificateAuthority(new CaConfiguration(
                            new CaProfileSet(
                                "rsa",
                                new CaProfile
                                {
                                    CertificateChain = [X509Certificate2.CreateFromPem(rsaCa.ExportCertificatePem())],
                                    Name = "rsa",
                                    CertificateValidity = TimeSpan.FromDays(90),
                                    CrlNumber = BigInteger.Zero,
                                    PrivateKey = rsaCa.GetRSAPrivateKey()!
                                },
                                new CaProfile
                                {
                                    CertificateChain = [X509Certificate2.CreateFromPem(ecdsaCa.ExportCertificatePem())],
                                    Name = "ecdsa",
                                    CertificateValidity = TimeSpan.FromDays(90),
                                    CrlNumber = BigInteger.Zero,
                                    PrivateKey = ecdsaCa.GetECDsaPrivateKey()!
                                }),
                            ["http://localhost/crl"],
                            [],
                            []))
                        .AddScepServer(
                            new ScepServerOptions { RaCertificate = ra, DefaultProfile = "rsa" },
                            new SharedSecretChallengeValidator(Challenge));
                })
                .Configure(app => app
                    .UseRouting()
                    .UseAuthorization()
                    .UseEndpoints(e => e.MapScepServer())))
            .Build();
        await _host.StartAsync().ConfigureAwait(false);
        _client = new ScepTestClient(_host.GetTestClient());
    }

    [When("a client asks for the CA capabilities")]
    public async Task WhenCaps() => _caps = await _client.GetCaCaps().ConfigureAwait(false);

    [Then("the capabilities include {string}, {string} and {string}")]
    public void ThenCapsInclude(string a, string b, string c)
    {
        var lines = _caps!.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains(a, lines);
        Assert.Contains(b, lines);
        Assert.Contains(c, lines);
    }

    [When("a client asks for the CA certificates")]
    public async Task WhenCaCert() => (_caCertContentType, _caCerts) = await _client.GetCaCert().ConfigureAwait(false);

    [Then("the response is a CA\\/RA certificate bundle")]
    public void ThenBundle() => Assert.Equal("application/x-x509-ca-ra-cert", _caCertContentType);

    [Then("the first certificate is the RA certificate")]
    public void ThenFirstIsRa() => Assert.Equal(_ra.Thumbprint, _caCerts[0].Thumbprint);

    [Then("the bundle contains the CA certificate")]
    public void ThenContainsCa() => Assert.Contains(_caCerts, c => c.Thumbprint == _rsaCa.Thumbprint);

    [When("a client enrolls with the challenge password {string} using the {string} profile")]
    public Task WhenEnroll(string challenge, string profile) => Enroll(challenge, profile, useGet: false);

    [When("a client enrolls through GET with the challenge password {string}")]
    public Task WhenEnrollGet(string challenge) => Enroll(challenge, "rsa", useGet: true);

    [When("a client enrolls without a challenge password")]
    public Task WhenEnrollWithout() => Enroll(null, "rsa", useGet: false);

    [When("a client enrolls with a request encrypted to a foreign certificate")]
    public async Task WhenEnrollForeign()
    {
        using var foreignKey = RSA.Create(2048);
        var foreign = ScepTestClient.CreateTransientSigner(foreignKey);
        _clientKey = RSA.Create(2048);
        _clientSigner = ScepTestClient.CreateTransientSigner(_clientKey);
        var client = new ScepTestClient(_host.GetTestClient());
        _response = await client.Enroll(
            ScepTestClient.CreateCsr(_clientKey, Subject, Challenge),
            _clientSigner, foreign, _transactionId, _senderNonce).ConfigureAwait(false);
    }

    [When("a client enrolls with a subject alternative name UPN {string}")]
    public async Task WhenEnrollUpn(string upn)
    {
        _clientKey = RSA.Create(2048);
        _clientSigner = ScepTestClient.CreateTransientSigner(_clientKey);
        var csr = ScepTestClient.CreateCsr(_clientKey, Subject, Challenge);
        var san = new SubjectAlternativeNameBuilder();
        san.AddUserPrincipalName(upn);
        csr.CertificateExtensions.Add(san.Build());
        _response = await new ScepTestClient(_host.GetTestClient(), "/scep/rsa")
            .Enroll(csr, _clientSigner, _ra, _transactionId, _senderNonce).ConfigureAwait(false);
        await ReadCertRep().ConfigureAwait(false);
    }

    [When("a client enrolls asking for basicConstraints CA:TRUE and keyCertSign")]
    public async Task WhenEnrollAsCa()
    {
        _clientKey = RSA.Create(2048);
        _clientSigner = ScepTestClient.CreateTransientSigner(_clientKey);
        var csr = ScepTestClient.CreateCsr(_clientKey, Subject, Challenge);
        csr.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        csr.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        _response = await new ScepTestClient(_host.GetTestClient(), "/scep/rsa")
            .Enroll(csr, _clientSigner, _ra, _transactionId, _senderNonce).ConfigureAwait(false);
        await ReadCertRep().ConfigureAwait(false);
    }

    private async Task Enroll(string? challenge, string profile, bool useGet)
    {
        _clientKey = RSA.Create(2048);
        _clientSigner = ScepTestClient.CreateTransientSigner(_clientKey);
        var client = new ScepTestClient(_host.GetTestClient(), $"/scep/{profile}");
        _response = await client.Enroll(
            ScepTestClient.CreateCsr(_clientKey, Subject, challenge),
            _clientSigner, _ra, _transactionId, _senderNonce, useGet).ConfigureAwait(false);
        await ReadCertRep().ConfigureAwait(false);
    }

    private async Task ReadCertRep()
    {
        Assert.Equal(HttpStatusCode.OK, _response!.StatusCode);
        Assert.Equal("application/x-pki-message", _response.Content.Headers.ContentType?.MediaType);
        var body = await _response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
        _certRep = ScepTestResponse.Read(body, _clientSigner!);
    }

    [Then("the server answers SUCCESS")]
    public void ThenSuccess()
    {
        Assert.Equal("3", _certRep!.MessageType);
        Assert.Equal("0", _certRep.PkiStatus);
        Assert.NotNull(_certRep.Issued);
    }

    [Then("the response echoes the transaction ID and the client's nonce")]
    public void ThenEchoes()
    {
        Assert.Equal(_transactionId, _certRep!.TransactionId);
        Assert.Equal(_senderNonce, _certRep.RecipientNonce);
    }

    [Then("the issued certificate has the requested subject")]
    public void ThenSubject() =>
        Assert.Equal(new X500DistinguishedName(Subject).Name, _certRep!.Issued!.SubjectName.Name);

    [Then("the issued certificate is issued by the {string} CA")]
    public void ThenIssuedBy(string profile)
    {
        var ca = profile == "rsa" ? _rsaCa : _ecdsaCa;
        Assert.Equal(ca.SubjectName.Name, _certRep!.Issued!.IssuerName.Name);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        Assert.True(chain.Build(_certRep.Issued), string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation)));
    }

    [Then("the server answers FAILURE with failInfo badRequest")]
    public void ThenFailureBadRequest()
    {
        Assert.Equal("2", _certRep!.PkiStatus);
        Assert.Equal("2", _certRep.FailInfo);
    }

    [Then("no certificate is returned")]
    public void ThenNoCertificate() => Assert.Null(_certRep!.Issued);

    [Then("the server rejects the message with HTTP {int}")]
    public void ThenHttpStatus(int status) => Assert.Equal((HttpStatusCode)status, _response!.StatusCode);

    [Then("the issued certificate contains the UPN {string}")]
    public void ThenUpn(string upn)
    {
        var san = _certRep!.Issued!.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        // .NET exposes no UPN enumerator; the otherName is matched in the DER.
        var der = san.RawData;
        var needle = System.Text.Encoding.UTF8.GetBytes(upn);
        Assert.True(der.AsSpan().IndexOf(needle) >= 0, "UPN not found in the subject alternative name.");
        Assert.True(der.AsSpan().IndexOf(new byte[] { 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03 }) >= 0,
            "The SAN does not carry the UPN otherName OID 1.3.6.1.4.1.311.20.2.3.");
    }

    public void Dispose()
    {
        _host?.Dispose();
        _clientKey?.Dispose();
        _clientSigner?.Dispose();
        _response?.Dispose();
    }
}
