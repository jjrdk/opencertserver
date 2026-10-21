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
    private X509Certificate2? _root;

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
    public Task GivenACertificateServer() => StartServer(withChallenge: true);

    [Given("a certificate server with SCEP but no challenge validator")]
    public Task GivenAServerWithoutValidator() => StartServer(withChallenge: false);

    [Given("a certificate server with SCEP whose CA is issued by a root")]
    public Task GivenAServerBelowARoot() => StartServer(withChallenge: true, belowRoot: true);

    private async Task StartServer(bool withChallenge, bool belowRoot = false)
    {
        var rsaKey = RSA.Create(2048);
        var rsaReq = new CertificateRequest("CN=SCEP Test RSA CA", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rsaReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rsaReq.PublicKey, false));
        rsaReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        if (belowRoot)
        {
            using var rootKey = RSA.Create(2048);
            var rootReq = new CertificateRequest("CN=SCEP Test Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            _root = rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddYears(2));
            _rsaCa = rsaReq.Create(_root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1),
                    RandomNumberGenerator.GetBytes(16))
                .CopyWithPrivateKey(rsaKey);
        }
        else
        {
            _rsaCa = rsaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
            rsaKey.Dispose();
        }

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
        // The issuing CA signs; the root is only published (EST /cacerts and SCEP GetCACert).
        X509Certificate2Collection published = _root is null
            ? []
            : [X509Certificate2.CreateFromPem(rsaCa.ExportCertificatePem()), X509Certificate2.CreateFromPem(_root.ExportCertificatePem())];
        _host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthorization();
                    services = services.AddInMemoryCertificateStore()
                        .AddCertificateAuthority(new CaConfiguration(
                            new CaProfileSet(
                                "rsa",
                                new CaProfile
                                {
                                    CertificateChain = [X509Certificate2.CreateFromPem(rsaCa.ExportCertificatePem())],
                                    PublishedCertificateChain = published,
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
                            []));
                    var options = new ScepServerOptions { RaCertificate = ra, DefaultProfile = "rsa" };
                    _ = withChallenge
                        ? services.AddScepServer(options, new SharedSecretChallengeValidator(Challenge))
                        : services.AddScepServer(options);
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

    [Then("the bundle contains the root certificate")]
    public void ThenContainsRoot() => Assert.Contains(_caCerts, c => c.Thumbprint == _root!.Thumbprint);

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

    // --- Renewal and replay ------------------------------------------------------

    private X509Certificate2? _held;
    private X509Certificate2? _renewed;
    private RSA? _newKey;

    [Given("a client holding a certificate from the {string} profile")]
    public async Task GivenHeldCertificate(string profile)
    {
        await Enroll(Challenge, profile, useGet: false).ConfigureAwait(false);
        ThenSuccess();
        _held = _certRep!.Issued!.CopyWithPrivateKey(_clientKey!);
    }

    [Given("that certificate is revoked")]
    public async Task GivenRevoked()
    {
        var ca = _host.Services.GetRequiredService<ICertificateAuthority>();
        Assert.True(await ca.RevokeCertificate(_held!.GetSerialNumberString(), X509RevocationReason.KeyCompromise)
            .ConfigureAwait(false));
    }

    [When("the client renews it with a new key")]
    public Task WhenRenew() => Renew(Subject, _held!);

    [When("the client renews it for the subject {string}")]
    public Task WhenRenewOtherSubject(string subject) => Renew(subject, _held!);

    [When("a client renews with a certificate from a look-alike CA of the same name")]
    public Task WhenRenewLookAlike()
    {
        // Same CA name, different key: the issuer name matches, the signature does not.
        using var fakeKey = RSA.Create(2048);
        var fakeReq = new CertificateRequest(_rsaCa.SubjectName, fakeKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        fakeReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var fakeCa = fakeReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var deviceKey = RSA.Create(2048);
        var deviceReq = new CertificateRequest(Subject, deviceKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var lookAlike = deviceReq.Create(fakeCa, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(1),
                RandomNumberGenerator.GetBytes(16))
            .CopyWithPrivateKey(deviceKey);
        Assert.Equal(_rsaCa.SubjectName.Name, lookAlike.IssuerName.Name);
        return Renew(Subject, lookAlike);
    }

    [When("the same request is sent again")]
    public async Task WhenSameAgain()
    {
        // Same transaction ID and nonce, as a replay of the captured message would carry.
        var client = new ScepTestClient(_host.GetTestClient(), "/scep/rsa");
        _response = await client.Enroll(
            ScepTestClient.CreateCsr(_clientKey!, Subject, Challenge),
            _clientSigner!, _ra, _transactionId, _senderNonce).ConfigureAwait(false);
        await ReadCertRep().ConfigureAwait(false);
    }

    private async Task Renew(string subject, X509Certificate2 signer)
    {
        _newKey = RSA.Create(2048);
        _clientSigner = signer;
        var client = new ScepTestClient(_host.GetTestClient(), "/scep/rsa");
        _response = await client.Enroll(
            ScepTestClient.CreateCsr(_newKey, subject, challenge: null),
            signer, _ra, Convert.ToHexString(RandomNumberGenerator.GetBytes(8)), RandomNumberGenerator.GetBytes(16),
            messageType: "17").ConfigureAwait(false);
        await ReadCertRep().ConfigureAwait(false);
        _renewed = _certRep!.Issued;
    }

    [Then("the renewed certificate has the same subject and a new key")]
    public void ThenRenewed()
    {
        Assert.Equal(_held!.SubjectName.Name, _renewed!.SubjectName.Name);
        Assert.NotEqual(_held.GetSerialNumberString(), _renewed.GetSerialNumberString());
        Assert.False(_held.PublicKey.EncodedKeyValue.RawData.AsSpan()
            .SequenceEqual(_renewed.PublicKey.EncodedKeyValue.RawData));
    }

    [Then("the previous certificate is revoked")]
    public async Task ThenPreviousRevoked()
    {
        var ca = _host.Services.GetRequiredService<ICertificateAuthority>();
        var crl = await ca.GetRevocationList("rsa").ConfigureAwait(false);
        var list = CertificateRevocationListBuilder.Load(crl, out _);
        Assert.True(list.RemoveEntry(Convert.FromHexString(_held!.GetSerialNumberString())),
            "The renewed certificate is not on the revocation list.");
    }

    private async Task Enroll(
        string? challenge, string profile, bool useGet,
        string encryptionOid = OpenCertServer.Ca.Utils.Oids.Aes128Cbc, byte[]? senderNonce = null,
        bool readReply = true)
    {
        _clientKey = RSA.Create(2048);
        _clientSigner = ScepTestClient.CreateTransientSigner(_clientKey);
        var client = new ScepTestClient(_host.GetTestClient(), $"/scep/{profile}");
        _response = await client.Enroll(
            ScepTestClient.CreateCsr(_clientKey, Subject, challenge),
            _clientSigner, _ra, _transactionId, senderNonce ?? _senderNonce, useGet,
            encryptionOid: encryptionOid).ConfigureAwait(false);
        if (readReply)
        {
            await ReadCertRep().ConfigureAwait(false);
        }
    }

    // --- Algorithms and nonces (RFC 8894, 2.9, 3.2.1, 3.5.2) -----------------

    private static readonly Dictionary<string, string> Algorithmen = new()
    {
        ["AES-128-CBC"] = OpenCertServer.Ca.Utils.Oids.Aes128Cbc,
        ["AES-256-CBC"] = OpenCertServer.Ca.Utils.Oids.Aes256Cbc,
        ["3DES-CBC"] = OpenCertServer.Ca.Utils.Oids.TripleDesCbc,
    };

    [When("a client enrolls with the challenge password {string} and the request encrypted with {string}")]
    public Task WhenEnrollEncryptedWith(string challenge, string algorithm) =>
        Enroll(challenge, "rsa", useGet: false, encryptionOid: Algorithmen[algorithm]);

    [Then("the reply is encrypted with {string}")]
    public void ThenReplyEncryptedWith(string algorithm) =>
        Assert.Equal(Algorithmen[algorithm], _certRep!.EncryptionAlgorithm);

    [When("a client enrolls with a senderNonce of {int} bytes")]
    public Task WhenEnrollWithNonceOf(int bytes) =>
        Enroll(Challenge, "rsa", useGet: false, senderNonce: RandomNumberGenerator.GetBytes(bytes), readReply: false);

    [Then("the server answers HTTP 400")]
    public void ThenHttp400() => Assert.Equal(HttpStatusCode.BadRequest, _response!.StatusCode);

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
        _held?.Dispose();
        _newKey?.Dispose();
        _clientKey?.Dispose();
        _clientSigner?.Dispose();
        _root?.Dispose();
        _response?.Dispose();
    }
}
