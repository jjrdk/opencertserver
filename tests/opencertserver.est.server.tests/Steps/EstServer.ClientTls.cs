namespace OpenCertServer.Est.Tests.Steps;

using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Est.Client;
using Reqnroll;
using Xunit;

public partial class EstServer
{
    private IHost? _tlsHost;
    private EstClient _tlsClient = null!;
    private EstClientOptions _tlsClientOptions = null!;
    private AsymmetricAlgorithm _tlsKey = null!;
    private AsymmetricAlgorithm? _renewalKey;
    private X509Certificate2 _tlsIdentity = null!;
    private X509Certificate2 _tlsRoot = null!;
    private X509Certificate2 _tlsEcRoot = null!;
    private string _tlsProfile = null!;
    private readonly ConcurrentQueue<(string Connection, string? Thumbprint, bool Header)> _tlsRequests = new();
    private X509Certificate2Collection? _tlsRenewed;
    private Exception? _tlsError;
    private bool _tlsAbortRequest;
    private CancellationTokenSource? _tlsCancellation;

    [Given("an EST client with a real TLS server and {string} identity")]
    public async Task GivenAnEstClientWithARealTlsServer(string algorithm)
    {
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _tlsRoot = CreateTlsRoot(rsa);
        _tlsEcRoot = CreateTlsRoot(ec);
        var webCertificate = algorithm == "RSA" ? _tlsRoot : _tlsEcRoot;
        _tlsHost = CreateHostBuilder(_tlsRoot, _tlsEcRoot, webCertificate, realTls: true,
            observeRequest: context =>
            {
                _tlsRequests.Enqueue((context.Connection.Id, context.Connection.ClientCertificate?.Thumbprint,
                    context.Request.Headers.ContainsKey("X-Client-Cert")));
                if (_tlsAbortRequest)
                {
                    context.Abort();
                }

                _tlsCancellation?.Cancel();
            }).Build();
        await _tlsHost.StartAsync();
        var address = _tlsHost.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()!.Addresses.Single();
        _tlsProfile = algorithm == "RSA" ? "rsa" : "ecdsa";
        _tlsKey = CreateTlsKey();
        var request = CreateTlsRequest(_tlsKey);
        var authority = _tlsHost.Services.GetRequiredService<ICertificateAuthority>();
        var signed = Assert.IsType<SignCertificateResponse.Success>(
            await authority.SignCertificateRequest(request, _tlsProfile));
        using var publicCertificate = signed.Certificate;
        _tlsIdentity = AttachTlsKey(publicCertificate, _tlsKey);
        _tlsClientOptions = new EstClientOptions
        {
            TrustAnchorMode = EstTrustAnchorMode.ExplicitOnly,
            AllowBootstrapCaCertsWithoutTrustedServer = true,
            RevocationMode = X509RevocationMode.NoCheck
        };
        _tlsClientOptions.ExplicitTrustAnchors.Add(webCertificate);
        _tlsClient = new EstClient(new Uri(address), _tlsClientOptions, _tlsProfile);
    }

    [When("the TLS client first makes an {string} request")]
    public async Task WhenTheTlsClientFirstMakesARequest(string initial)
    {
        if (initial == "bootstrap")
        {
            _tlsClientOptions.ExplicitTrustAnchors.Clear();
            Assert.NotEmpty(await _tlsClient.ServerCertificates());
            Assert.NotNull(_tlsClient.PendingBootstrapTrust);
            _tlsClient.AcceptBootstrapTrust();
        }
        else if (initial == "cacerts")
        {
            Assert.NotEmpty(await _tlsClient.ServerCertificates());
        }
        else
        {
            var (error, certificates) = await _tlsClient.Enroll(_tlsIdentity.SubjectName, _tlsKey,
                X509KeyUsageFlags.DigitalSignature);
            Assert.NotNull(error);
            Assert.Null(certificates);
        }

        Assert.Null(_tlsRequests.Last().Thumbprint);
    }

    [When("the TLS client renews using {string} key material")]
    public async Task WhenTheTlsClientRenewsUsingKeyMaterial(string material)
    {
        _renewalKey = material == "renewal" ? CreateTlsKey() : null;
        using var publicCertificate = X509CertificateLoader.LoadCertificate(_tlsIdentity.RawData);
        var (error, certificates) = await _tlsClient.ReEnroll(_renewalKey ?? _tlsKey,
            material == "public" ? publicCertificate : _tlsIdentity);
        Assert.Null(error);
        _tlsRenewed = certificates;
    }

    [Then("renewal uses the existing certificate over a new TLS connection")]
    public void ThenRenewalUsesTheExistingCertificateOverTls()
    {
        Assert.NotNull(_tlsRenewed);
        Assert.NotEmpty(_tlsRenewed);
        var requests = _tlsRequests.ToArray();
        Assert.Equal(_tlsIdentity.Thumbprint, requests[1].Thumbprint);
        Assert.NotEqual(requests[0].Connection, requests[1].Connection);
        Assert.All(requests, request => Assert.False(request.Header));
        using var renewedKey = _tlsRenewed[0].GetRSAPublicKey() ??
            (AsymmetricAlgorithm?)_tlsRenewed[0].GetECDsaPublicKey();
        Assert.Equal((_renewalKey ?? _tlsKey).ExportSubjectPublicKeyInfo(),
            renewedKey!.ExportSubjectPublicKeyInfo());
    }

    [Then("certificate enrollment and anonymous CA retrieval use isolated TLS connections")]
    public async Task ThenCertificateEnrollmentAndAnonymousRetrievalAreIsolated()
    {
        var (error, certificates) = await _tlsClient.Enroll(_tlsIdentity.SubjectName, _tlsKey,
            X509KeyUsageFlags.DigitalSignature, certificate: _tlsIdentity);
        Assert.Null(error);
        Assert.NotEmpty(certificates!);
        var firstIdentityConnection = _tlsRequests.Last().Connection;
        Assert.Equal(_tlsIdentity.Thumbprint, _tlsRequests.Last().Thumbprint);
        await _tlsClient.ServerCertificates();
        Assert.Null(_tlsRequests.Last().Thumbprint);
        Assert.NotEqual(firstIdentityConnection, _tlsRequests.Last().Connection);

        (error, _) = await _tlsClient.Enroll(_tlsIdentity.SubjectName, _tlsKey,
            X509KeyUsageFlags.DigitalSignature, certificate: _tlsIdentity);
        Assert.Null(error);
        var previousIdentityConnection = _tlsRequests.Last().Connection;
        using var secondIdentity = AttachTlsKey(certificates![0], _tlsKey);
        (error, certificates) = await _tlsClient.ReEnroll(_tlsKey, secondIdentity);
        Assert.Null(error);
        Assert.NotEmpty(certificates!);
        Assert.Equal(secondIdentity.Thumbprint, _tlsRequests.Last().Thumbprint);
        Assert.NotEqual(previousIdentityConnection, _tlsRequests.Last().Connection);
        Assert.All(_tlsRequests, request => Assert.False(request.Header));
    }

    [When("the TLS client renews a public certificate with an unrelated private key")]
    public async Task WhenTheTlsClientRenewsWithAnUnrelatedKey()
    {
        using var key = CreateTlsKey();
        using var publicCertificate = X509CertificateLoader.LoadCertificate(_tlsIdentity.RawData);
        _tlsError = await Record.ExceptionAsync(() => _tlsClient.ReEnroll(key, publicCertificate));
    }

    [Then("the client rejects the mismatched key without sending a request")]
    public void ThenTheClientRejectsTheMismatchedKey()
    {
        Assert.IsType<ArgumentException>(_tlsError);
        Assert.Empty(_tlsRequests);
    }

    [When("a TLS certificate request is {string} after reaching the server")]
    public async Task WhenATlsCertificateRequestFails(string failure)
    {
        using var cancellation = new CancellationTokenSource();
        _tlsAbortRequest = failure == "aborted";
        _tlsCancellation = failure == "cancelled" ? cancellation : null;
        using var publicCertificate = X509CertificateLoader.LoadCertificate(_tlsIdentity.RawData);
        _tlsError = await Record.ExceptionAsync(() => _tlsClient.ReEnroll(_tlsKey, publicCertificate,
            cancellation.Token));
        _tlsCancellation = null;
        _tlsAbortRequest = false;
        Assert.NotNull(_tlsError);
        if (failure == "cancelled")
        {
            Assert.IsAssignableFrom<OperationCanceledException>(_tlsError);
        }
        else
        {
            Assert.IsType<HttpRequestException>(_tlsError);
        }
    }

    [Then("subsequent CA retrieval does not present the failed request's certificate")]
    public async Task ThenSubsequentRetrievalHasNoCertificate()
    {
        Assert.NotEmpty(await _tlsClient.ServerCertificates());
        var requests = _tlsRequests.ToArray();
        Assert.Equal(_tlsIdentity.Thumbprint, requests[0].Thumbprint);
        Assert.Null(requests.Last().Thumbprint);
        Assert.NotEqual(requests[0].Connection, requests.Last().Connection);
        Assert.All(requests, request => Assert.False(request.Header));
    }

    [AfterScenario("@est-client-tls")]
    public async Task CleanupTlsClient()
    {
        _tlsClient.Dispose();
        if (_tlsHost != null)
        {
            await _tlsHost.StopAsync();
            _tlsHost.Dispose();
        }

        _tlsIdentity.Dispose();
        _tlsKey.Dispose();
        _renewalKey?.Dispose();
        _tlsRoot.Dispose();
        _tlsEcRoot.Dispose();
    }

    private AsymmetricAlgorithm CreateTlsKey() => _tlsProfile == "rsa"
        ? RSA.Create(2048)
        : ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private static X509Certificate2 AttachTlsKey(X509Certificate2 certificate, AsymmetricAlgorithm key) => key switch
    {
        RSA rsa => certificate.CopyWithPrivateKey(rsa),
        ECDsa ecdsa => certificate.CopyWithPrivateKey(ecdsa),
        _ => throw new NotSupportedException()
    };

    private static CertificateRequest CreateTlsRequest(AsymmetricAlgorithm key, string subject = "CN=test")
    {
        var request = key switch
        {
            RSA rsa => new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException()
        };
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.2")], false));
        return request;
    }

    private static X509Certificate2 CreateTlsRoot(AsymmetricAlgorithm key)
    {
        var request = CreateTlsRequest(key, key is RSA ? "CN=RSA TLS CA" : "CN=ECDsa TLS CA");
        request.CertificateExtensions.Clear();
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign, true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(System.Net.IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
