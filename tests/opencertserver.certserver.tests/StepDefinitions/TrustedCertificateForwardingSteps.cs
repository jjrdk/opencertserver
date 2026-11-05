namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Est.Server;
using Reqnroll;
using Xunit;

[Binding]
public sealed class TrustedCertificateForwardingSteps
{
    private IHost? _host;
    private X509Certificate2? _issuer;
    private X509Certificate2? _certificate;
    private HttpStatusCode _status;
    private string? _identity;
    private Exception? _configurationError;
    private string _certificateHeader = "X-Client-Cert";

    [Given("certificate forwarding is {string}")]
    public async Task GivenForwarding(string mode)
    {
        _certificateHeader = mode == "custom" ? "X-Verified-Client-Certificate" : "X-Client-Cert";
        using var issuerKey = RSA.Create(2048);
        var issuerRequest = new CertificateRequest("CN=Proxy test CA", issuerKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        _issuer = issuerRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10));
        using var clientKey = RSA.Create(2048);
        var clientRequest = new CertificateRequest("CN=victim", clientKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        clientRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        clientRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true));
        _certificate = clientRequest.Create(_issuer, DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        Assert.False(_certificate.HasPrivateKey);
        _host = await new HostBuilder().ConfigureWebHost(builder => builder.UseTestServer()
            .ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddAuthorization();
                services.AddAuthentication(options =>
                    {
                        options.DefaultAuthenticateScheme = CertificateAuthenticationDefaults.AuthenticationScheme;
                        options.DefaultChallengeScheme = "Bearer";
                    })
                    .AddJwtBearer()
                    .AddCertificate(options =>
                    {
                        options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
                        options.CustomTrustStore.Add(_issuer);
                        options.RevocationMode = X509RevocationMode.NoCheck;
                    });
                var values = new Dictionary<string, string?>
                {
                    ["CertificateForwarding:Enabled"] = (mode != "default").ToString(),
                    ["CertificateForwarding:CertificateHeader"] = _certificateHeader
                };
                values[mode == "network"
                    ? "CertificateForwarding:KnownNetworks:0"
                    : "CertificateForwarding:KnownProxies:0"] = mode == "network" ? "192.0.2.0/24" : "192.0.2.10";
                Assert.Equal(mode != "default", Program.ConfigureCertificateForwarding(services,
                    new ConfigurationBuilder().AddInMemoryCollection(values).Build()));
            })
            .Configure(app =>
            {
                if (mode != "default")
                {
                    app.UseTrustedCertificateForwarding();
                }

                // Deliberately permissive address forwarding must not grant certificate trust.
                var forwarded = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor };
                forwarded.KnownProxies.Clear();
                forwarded.KnownIPNetworks.Clear();
                app.UseForwardedHeaders(forwarded);
                var policy = new AuthorizationPolicyBuilder("Certificate", "Bearer")
                    .RequireAuthenticatedUser().Build();
                app.UseEstServer(enrollPolicy: policy, reEnrollPolicy: policy);
                app.UseEndpoints(endpoints => endpoints.MapPost("/probe",
                    (HttpContext context) => Results.Text(context.User.Identity!.Name!)).RequireAuthorization());
            })).StartAsync();
    }

    [When("peer {string} sends a genuine certificate header to {string}")]
    public async Task WhenHeader(string peer, string endpoint)
    {
        var response = await _host!.GetTestServer().SendAsync(context =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse(peer);
            context.Request.Scheme = "https";
            context.Request.Method = "POST";
            context.Request.Path = endpoint == "probe" ? "/probe" : $"/.well-known/est/{endpoint}";
            context.Request.Headers[_certificateHeader] = Convert.ToBase64String(_certificate!.RawData);
        });
        _status = (HttpStatusCode)response.Response.StatusCode;
        if (peer.StartsWith("198.", StringComparison.Ordinal))
        {
            Assert.False(response.Request.Headers.ContainsKey(_certificateHeader));
        }
    }

    [When("an untrusted peer forges a trusted forwarded address")]
    public async Task WhenForgedAddress()
    {
        var response = await _host!.GetTestServer().SendAsync(context =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.20");
            context.Request.Scheme = "https";
            context.Request.Method = "POST";
            context.Request.Path = "/probe";
            context.Request.Headers["X-Forwarded-For"] = "192.0.2.10";
            context.Request.Headers["X-Client-Cert"] = Convert.ToBase64String(_certificate!.RawData);
        });
        Assert.Equal(IPAddress.Parse("192.0.2.10"), response.Connection.RemoteIpAddress);
        Assert.False(response.Request.Headers.ContainsKey("X-Client-Cert"));
        _status = (HttpStatusCode)response.Response.StatusCode;
    }

    [Then("the forwarded certificate request returns {int}")]
    public void ThenStatus(int status) => Assert.Equal((HttpStatusCode)status, _status);

    [When("an untrusted peer sends a victim header with its own TLS certificate")]
    public async Task WhenTlsIdentity()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=actual-client", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.2") }, true));
        using var tlsCertificate = request.Create(_issuer!, DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        var response = await _host!.GetTestServer().SendAsync(context =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Parse("198.51.100.20");
            context.Connection.ClientCertificate = tlsCertificate;
            context.Request.Scheme = "https";
            context.Request.Method = "POST";
            context.Request.Path = "/probe";
            context.Request.Headers["X-Client-Cert"] = Convert.ToBase64String(_certificate!.RawData);
        });
        Assert.False(response.Request.Headers.ContainsKey("X-Client-Cert"));
        _status = (HttpStatusCode)response.Response.StatusCode;
        using var reader = new StreamReader(response.Response.Body);
        _identity = await reader.ReadToEndAsync();
    }

    [Then("only the TLS certificate identity is authenticated")]
    public void ThenTlsIdentity()
    {
        Assert.Equal(HttpStatusCode.OK, _status);
        Assert.Equal("actual-client", _identity);
    }

    [When("certificate forwarding is enabled with {string}")]
    public void WhenInvalidConfiguration(string configuration)
    {
        var values = new Dictionary<string, string?> { ["CertificateForwarding:Enabled"] = "true" };
        if (configuration != "missing header")
        {
            values["CertificateForwarding:CertificateHeader"] =
                configuration == "invalid header" ? "X-Client-Cert\r\n" : "X-Client-Cert";
        }

        if (configuration != "missing proxies")
        {
            values["CertificateForwarding:KnownProxies:0"] =
                configuration == "invalid proxy" ? "not-an-address" : "192.0.2.10";
        }

        if (configuration == "invalid network")
        {
            values["CertificateForwarding:KnownNetworks:0"] = "not-a-network";
        }

        _configurationError = Record.Exception(() => Program.ConfigureCertificateForwarding(
            new ServiceCollection(), new ConfigurationBuilder().AddInMemoryCollection(values).Build()));
    }

    [Then("certificate forwarding configuration is rejected")]
    public void ThenRejected() => Assert.NotNull(_configurationError);

    [AfterScenario("trusted-certificate-forwarding")]
    public void Cleanup()
    {
        _host?.Dispose();
        _certificate?.Dispose();
        _issuer?.Dispose();
    }
}
