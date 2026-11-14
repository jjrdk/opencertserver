namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Reqnroll;
using Xunit;

public sealed partial class ApplianceUpgradeSteps
{
    private string? _network;
    private string? _caContainer;
    private WebApplication? _identityProvider;
    private X509Certificate2? _issuerTls;
    private string? _operatorToken;
    private string? _issuedSerial;

    [Given("a hardened CA and RA container topology")]
    public async Task CaAndRaTopology()
    {
        var image = Environment.GetEnvironmentVariable("OPENCERT_APPLIANCE_TEST_IMAGE");
        Assert.SkipWhen(string.IsNullOrWhiteSpace(image), "Set OPENCERT_APPLIANCE_TEST_IMAGE to a built Linux image.");
        HardenedConfiguration();
        var config = ApplianceConfiguration.ReadDocument(Source);
        config["AllowedHosts"] = "localhost;ca";
        config["Ca"] = new JsonObject
        {
            ["AcceptRa"] = true,
            ["RaBindings"] = new JsonArray(new JsonObject
            {
                ["RaId"] = "ra-tenant-a", ["Scopes"] = new JsonArray("tenant.example.test"),
                ["Profiles"] = new JsonArray("rsa")
            })
        };
        _network = "opencert-topology-" + Guid.NewGuid().ToString("N");
        var network = await Execute("docker", ["network", "create", _network]);
        Assert.True(network.ExitCode == 0, network.Error);
        using var root = X509Certificate2.CreateFromPemFile(
            Path.Combine(_directory, "rsa.pem"), Path.Combine(_directory, "rsa.key"));
        using var identityKey = RSA.Create(2048);
        var identityRequest = new CertificateRequest("CN=ra-tenant-a", identityKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        identityRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, false));
        var crlPort = FreePort();
        identityRequest.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(
            [$"http://host.docker.internal:{crlPort}/ra.crl"]));
        using var identity = identityRequest.Create(root, DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        await File.WriteAllTextAsync(Path.Combine(_directory, "ra.pem"), identity.ExportCertificatePem());
        await File.WriteAllTextAsync(Path.Combine(_directory, "ra.key"), identityKey.ExportPkcs8PrivateKeyPem());
        var crl = new CertificateRevocationListBuilder().Build(root, BigInteger.One,
            DateTimeOffset.UtcNow.AddDays(1), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var issuerPort = FreePort();
        var issuer = $"https://host.docker.internal:{issuerPort}";
        using var operatorKey = RSA.Create(2048);
        var parameters = operatorKey.ExportParameters(false);
        var keySet = new JsonObject
        {
            ["keys"] = new JsonArray(new JsonObject
            {
                ["kty"] = "RSA", ["use"] = "sig", ["kid"] = "operator", ["alg"] = "RS256",
                ["n"] = Base64UrlEncoder.Encode(parameters.Modulus!),
                ["e"] = Base64UrlEncoder.Encode(parameters.Exponent!)
            })
        }.ToJsonString();
        var metadata = new JsonObject
        {
            ["issuer"] = issuer, ["jwks_uri"] = issuer + "/keys",
            ["id_token_signing_alg_values_supported"] = new JsonArray("RS256")
        }.ToJsonString();
        _operatorToken = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer, Audience = "appliance", Expires = DateTime.UtcNow.AddMinutes(10),
            Claims = new Dictionary<string, object> { ["sub"] = "operator", ["role"] = "ra_operator" },
            SigningCredentials = new SigningCredentials(
                new RsaSecurityKey(operatorKey) { KeyId = "operator" }, SecurityAlgorithms.RsaSha256)
        });
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            { EnvironmentName = "Testing", ContentRootPath = _directory });
        _issuerTls = X509Certificate2.CreateFromPemFile(
            Path.Combine(_directory, "tls.pem"), Path.Combine(_directory, "tls.key"));
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenAnyIP(issuerPort, listener => listener.UseHttps(_issuerTls));
            options.ListenAnyIP(crlPort);
        });
        _identityProvider = builder.Build();
        _identityProvider.MapGet("/.well-known/openid-configuration", () => Results.Text(metadata, "application/json"));
        _identityProvider.MapGet("/keys", () => Results.Text(keySet, "application/json"));
        _identityProvider.MapGet("/ra.crl", () => Results.Bytes(crl, "application/pkix-crl"));
        await _identityProvider.StartAsync();
        config["Jwt"]!["Authority"] = issuer;
        await File.WriteAllTextAsync(Source, config.ToJsonString());
        await StartContainer(Environment.GetEnvironmentVariable("OPENCERT_APPLIANCE_TEST_CA_IMAGE") ?? image!);
        _caContainer = _container;
        _container = null;
        _port = FreePort();
        config["Appliance"]!["Role"] = "Ra";
        config.Remove("rsa");
        config.Remove("ecdsa");
        config.Remove("Ca");
        config["Ra"] = new JsonObject
        {
            ["PeerUrl"] = "https://ca:5001/", ["Scope"] = "tenant.example.test", ["Profile"] = "rsa",
            ["ClientCertificatePath"] = Path.Combine(_directory, "ra.pem"),
            ["ClientPrivateKeyPath"] = Path.Combine(_directory, "ra.key"),
            ["CaTrustRoots"] = new JsonArray(Path.Combine(_directory, "tls.pem"))
        };
        var raConfigPath = Path.Combine(_directory, "ra-config.json");
        await File.WriteAllTextAsync(raConfigPath, config.ToJsonString());
        // The CA holds its original file mount; replacing a different path avoids changing its configuration.
        File.Move(raConfigPath, Source, overwrite: true);
        await StartContainer(Environment.GetEnvironmentVariable("OPENCERT_APPLIANCE_TEST_RA_IMAGE") ?? image!);
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    [When("an authorized RA operator enrolls an in-scope certificate")]
    public async Task EnrollThroughRa()
    {
        var response = await OperatorEnroll("host.tenant.example.test");
        var logs = response.Status == 200 ? "" : (await Execute("docker", ["logs", _container!])).Output;
        var caLogs = response.Status == 200 ? "" : (await Execute("docker", ["logs", _caContainer!])).Output;
        Assert.True(response.Status == 200, $"RA status {response.Status}: {response.Body}\n{logs}\n{caLogs}");
    }

    private async Task<(int Status, string Body)> OperatorEnroll(string name)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(name);
        request.CertificateExtensions.Add(names.Build());
        var csr = Path.Combine(_directory, "request.csr");
        var body = Path.Combine(_directory, "response.txt");
        await File.WriteAllTextAsync(csr, request.CreateSigningRequestPem());
        var result = await Execute("curl",
        [
            "--silent", "--show-error", "--noproxy", "*", "--max-time", "30",
            "--cacert", Path.Combine(_directory, "tls.pem"), "--tlsv1.3",
            "--header", "Authorization: Bearer " + _operatorToken,
            "--data-binary", "@" + csr, "--output", body, "--write-out", "%{http_code}",
            $"https://localhost:{_port}/ra/enroll"
        ]);
        Assert.True(result.ExitCode == 0, result.Error);
        return (int.Parse(result.Output), await File.ReadAllTextAsync(body));
    }

    [Then("the certificate is signed by the remote CA")]
    public void RemoteSignature()
    {
        using var certificate =
            X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(_directory, "response.txt")));
        using var root = X509Certificate2.CreateFromPem(File.ReadAllText(Path.Combine(_directory, "rsa.pem")));
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        Assert.True(chain.Build(certificate));
        Assert.Equal("CN=host.tenant.example.test", certificate.Subject);
        _issuedSerial = certificate.SerialNumber;
    }

    [Then("the remote CA rejects an out-of-scope operator enrollment")]
    public async Task RejectOutsideScope()
    {
        var response = await OperatorEnroll("outside.example.test");
        var logs = response.Status == 400 ? "" : (await Execute("docker", ["logs", _container!])).Output;
        Assert.True(response.Status == 400, $"RA status {response.Status}: {response.Body}\n{logs}");
        Assert.Equal(400, JsonNode.Parse(response.Body)!["status"]!.GetValue<int>());
    }

    [Then("the RA rejects malformed operator requests")]
    public async Task RejectMalformedOperatorRequests()
    {
        foreach (var (method, path) in new[]
            {
                ("POST", "/ra/enroll"),
                ("DELETE", "/ra/revoke?sn=0123&reason=1"),
                ("DELETE", "/ra/revoke?sn=0123&reason=NotAReason")
            })
        {
            var result = await Execute("curl",
            [
                "--silent", "--show-error", "--noproxy", "*", "--max-time", "10",
                "--cacert", Path.Combine(_directory, "tls.pem"), "--tlsv1.3",
                "--header", "Authorization: Bearer " + _operatorToken, "--request", method,
                "--output", Path.Combine(_directory, "invalid.txt"), "--write-out", "%{http_code}",
                $"https://localhost:{_port}{path}"
            ]);
            Assert.True(result.ExitCode == 0, result.Error);
            Assert.Equal("400", result.Output);
        }
    }

    [Then("the RA operator revokes the in-scope certificate")]
    public async Task RevokeThroughRa()
    {
        var result = await Execute("curl",
        [
            "--silent", "--show-error", "--noproxy", "*", "--max-time", "30",
            "--cacert", Path.Combine(_directory, "tls.pem"), "--tlsv1.3",
            "--header", "Authorization: Bearer " + _operatorToken, "--request", "DELETE",
            "--output", Path.Combine(_directory, "revocation.txt"), "--write-out", "%{http_code}",
            $"https://localhost:{_port}/ra/revoke?sn={_issuedSerial}&reason=CessationOfOperation"
        ]);
        Assert.True(result.ExitCode == 0, result.Error);
        Assert.Equal("204", result.Output);
    }

    private void DisposeRaTopology()
    {
        if (_caContainer != null)
        {
            Execute("docker", ["rm", "--force", _caContainer]).GetAwaiter().GetResult();
        }

        if (_network != null)
        {
            Execute("docker", ["network", "rm", _network]).GetAwaiter().GetResult();
        }

        if (_identityProvider != null)
        {
            _identityProvider.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        _issuerTls?.Dispose();
    }
}
