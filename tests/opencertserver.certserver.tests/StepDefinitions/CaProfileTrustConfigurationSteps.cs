namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils.Ca;
using Reqnroll;
using Xunit;

[Binding]
public sealed class CaProfileTrustConfigurationSteps
{
    private readonly List<string> _files = [];
    private readonly List<X509Certificate2> _certificates = [];
    private readonly RSA _key = RSA.Create();
    private CaProfile? _profile;
    private Exception? _error;
    private string _invalidTrustFile = "";
    private string _chainPath = "";
    private string _keyPath = "";
    private string _trustPath = "";
    private string _extraPath = "";
    private string _publishedPath = "";

    [Given("PEM files for an issuing chain and external client trust")]
    public void GivenPemFiles()
    {
        var root = CreateCertificate("CN=Issuing Root", true);
        var request = new CertificateRequest("CN=Issuing Intermediate", _key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var issuer = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(30), RandomNumberGenerator.GetBytes(16));
        _certificates.Add(issuer);
        _chainPath = WriteFile(issuer.ExportCertificatePem() + "\n" + root.ExportCertificatePem());
        _keyPath = WriteFile(_key.ExportPkcs8PrivateKeyPem());
        _trustPath = WriteFile(CreateCertificate("CN=External Client Root", true).ExportCertificatePem());
        _extraPath = WriteFile(CreateCertificate("CN=External Chain Certificate", true).ExportCertificatePem());
        _publishedPath = WriteFile(CreateCertificate("CN=Publication Supplement", true).ExportCertificatePem());
    }

    [When("a CA profile is loaded with {string} trust settings")]
    public async Task WhenAProfileIsLoaded(string shape)
    {
        var suffix = shape == "array" ? ":0" : "";
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"rsa:TrustAnchors{suffix}"] = _trustPath,
            [$"rsa:AdditionalChainCertificates{suffix}"] = _extraPath,
            ["rsa:PublishedPem"] = _publishedPath
        }).Build();
        _profile = await LoadProfile(configuration).ConfigureAwait(false);
    }

    [Then("the profile contains its issuing chain and separate external client trust")]
    public void ThenProfileTrustIsSeparate()
    {
        Assert.NotNull(_profile);
        Assert.Equal(2, _profile.CertificateChain.Count);
        Assert.Equal("CN=Issuing Intermediate", _profile.CertificateChain[0].Subject);
        Assert.Equal("CN=Issuing Root", _profile.CertificateChain[1].Subject);
        Assert.Equal("CN=External Client Root", Assert.Single(_profile.TrustAnchors).Subject);
        Assert.Equal("CN=External Chain Certificate", Assert.Single(_profile.AdditionalChainCertificates).Subject);
    }

    [Then("its published CA bundle contains the issuing chain and publication supplements only")]
    public async Task ThenPublicationContainsTheCompleteIssuingChain()
    {
        Assert.NotNull(_profile);
        using var profiles = new CaProfileSet("rsa", _profile);
        using var services = new ServiceCollection().AddLogging().AddInMemoryCertificateStore()
            .AddCertificateAuthority(new CaConfiguration(profiles, [], [], [])).BuildServiceProvider();
        var ca = services.GetRequiredService<ICertificateAuthority>();
        var published = await ca.GetPublishedCertificates("rsa").ConfigureAwait(false);
        Assert.Equal(3, published.Count);
        Assert.Equal(new[] { "CN=Issuing Intermediate", "CN=Issuing Root", "CN=Publication Supplement" },
            published.Select(certificate => certificate.Subject));

        using var key = RSA.Create();
        var request = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var result = await ca.SignCertificateRequest(request, "rsa").ConfigureAwait(false);
        using var issued = Assert.IsType<SignCertificateResponse.Success>(result).Certificate;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.CustomTrustStore.Add(_profile.CertificateChain[^1]);
        chain.ChainPolicy.ExtraStore.AddRange(published);
        Assert.True(chain.Build(issued), string.Join(", ", chain.ChainStatus.Select(status => status.Status)));
        _profile = null;
    }

    [When("a CA profile is loaded with a {string} trust file")]
    public async Task WhenAnInvalidFileIsConfigured(string invalid)
    {
        _invalidTrustFile = invalid;
        var path = invalid switch
        {
            "missing" => _trustPath + ".missing",
            "empty" => WriteFile(""),
            "non-CA" => WriteFile(CreateCertificate("CN=Not a CA", false).ExportCertificatePem()),
            "no certificate sign" => WriteFile(CreateCertificate("CN=Cannot sign", true,
                X509KeyUsageFlags.DigitalSignature).ExportCertificatePem()),
            _ => throw new ArgumentOutOfRangeException(nameof(invalid))
        };
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["rsa:TrustAnchors"] = path
        }).Build();
        _error = await Record.ExceptionAsync(async () =>
            _profile = await LoadProfile(configuration).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [Then("profile trust configuration fails")]
    public void ThenConfigurationFails()
    {
        switch (_invalidTrustFile)
        {
            case "missing":
                Assert.IsType<FileNotFoundException>(_error);
                break;
            case "empty":
                Assert.IsType<InvalidOperationException>(_error);
                break;
            default:
                Assert.IsType<ArgumentException>(_error);
                break;
        }
    }

    [Then("a non-CA certificate cannot be configured as profile trust")]
    public void ThenNonCaTrustIsRejected()
    {
        var certificate = CreateCertificate("CN=Not a CA", false);
        Assert.Throws<ArgumentException>(() => new CaProfile
        {
            Name = "invalid",
            PrivateKey = _key,
            CertificateChain = [],
            TrustAnchors = [certificate]
        });
        Assert.Throws<ArgumentException>(() => new CaProfile
        {
            Name = "invalid",
            PrivateKey = _key,
            CertificateChain = [],
            AdditionalChainCertificates = [certificate]
        });
    }

    [Then("its explicit client trust survives CA rollover and closing the publication window")]
    public void ThenClientTrustSurvivesRollover()
    {
        Assert.NotNull(_profile);
        _profile.TrustAnchors.Add(_profile.CertificateChain[^1]);
        _profile.AdditionalChainCertificates.Add(_profile.PublishedCertificateChain[^1]);
        var trustedCertificates = _profile.TrustAnchors.Concat(_profile.AdditionalChainCertificates)
            .Select(certificate => certificate.RawData).ToArray();
        var replacement = CreateCertificate("CN=Issuing Intermediate", true);
        _profile.RollOver(replacement, replacement.GetRSAPrivateKey()!);
        _profile.CloseRolloverWindow();
        Assert.Single(_profile.CertificateChain);
        Assert.Single(_profile.PublishedCertificateChain);
        Assert.Equal(trustedCertificates,
            _profile.TrustAnchors.Concat(_profile.AdditionalChainCertificates)
                .Select(certificate => certificate.RawData).ToArray());
    }

    private Task<CaProfile> LoadProfile(IConfiguration configuration) =>
        Program.CreateProfile(["--rsa", _chainPath, "--rsa-key", _keyPath], configuration,
            "rsa", "--rsa", "--rsa-key", "--rsa-published", certificate => certificate.GetRSAPrivateKey());

    private X509Certificate2 CreateCertificate(
        string subject,
        bool ca,
        X509KeyUsageFlags usage = X509KeyUsageFlags.KeyCertSign)
    {
        using var key = RSA.Create();
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));
        _certificates.Add(certificate);
        return certificate;
    }

    private string WriteFile(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), $"opencert-profile-trust-{Guid.NewGuid():N}.pem");
        _files.Add(path);
        File.WriteAllText(path, content);
        return path;
    }

    [AfterScenario("profile-trust-config")]
    public void Cleanup()
    {
        _profile?.Dispose();
        _key.Dispose();
        foreach (var certificate in _certificates)
        {
            certificate.Dispose();
        }

        foreach (var file in _files)
        {
            File.Delete(file);
        }
    }
}
