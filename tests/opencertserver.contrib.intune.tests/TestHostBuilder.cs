namespace OpenCertServer.Contrib.Intune.Tests;

using System.Numerics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Scep.Server;

/// <summary>
/// A CA with an RSA and an ECDSA profile, the SCEP server and the Intune package wired to
/// <see cref="FakeIntune"/> - the same shape as the SCEP server tests, plus Intune.
/// </summary>
public sealed class TestHostBuilder
{
    public const string SyncRole = "intune-sync";
    public const string AuthenticationScheme = "Test";

    public static (IHost Host, X509Certificate2 RsaCa, X509Certificate2 Ra) Build(
        FakeIntune fake, int maxRevocations = 25, bool withCertificate = false)
    {
        using var rsaKey = RSA.Create(2048);
        var rsaReq = new CertificateRequest("CN=Intune Test RSA CA", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        AddCaExtensions(rsaReq);
        var rsaCa = rsaReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecReq = new CertificateRequest("CN=Intune Test ECDSA CA", ecKey, HashAlgorithmName.SHA256);
        AddCaExtensions(ecReq);
        var ecdsaCa = ecReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        var raKey = RSA.Create(2048);
        var raReq = new CertificateRequest("CN=Intune Test RA", raKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        raReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        var ra = raReq.Create(rsaCa, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(6), RandomNumberGenerator.GetBytes(16))
            .CopyWithPrivateKey(raKey);

        string? certificateFile = null, keyFile = null;
        if (withCertificate)
        {
            // The app's credential: a self-signed certificate whose public half "went to Entra"
            // (here: to the fake), the key stays with the server as two PEM files.
            using var appKey = RSA.Create(2048);
            var appReq = new CertificateRequest("CN=netzpass-ca", appKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var appCert = appReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
            fake.AppCertificate = X509Certificate2.CreateFromPem(appCert.ExportCertificatePem());
            var folder = Path.Combine(Path.GetTempPath(), "intune-app-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            certificateFile = Path.Combine(folder, "entra-cert.pem");
            keyFile = Path.Combine(folder, "entra-key.pem");
            File.WriteAllText(certificateFile, appCert.ExportCertificatePem());
            File.WriteAllText(keyFile, appKey.ExportPkcs8PrivateKeyPem());
        }

        var options = new IntuneOptions
        {
            TenantId = FakeIntune.Tenant,
            ClientId = "11111111-aaaa-bbbb-cccc-222222222222",
            ClientSecret = withCertificate ? null : "test-secret",
            ClientCertificateFile = certificateFile,
            ClientCertificateKeyFile = keyFile,
            CallerInfo = "OpenCertServer tests",
            MaxRevocationsPerSync = maxRevocations
        };

        var host = new HostBuilder()
            .ConfigureWebHost(web => web
                .UseTestServer()
                .ConfigureLogging(l => l.SetMinimumLevel(LogLevel.Warning))
                .ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddAuthentication(AuthenticationScheme)
                        .AddScheme<AuthenticationSchemeOptions, HeaderRoleHandler>(AuthenticationScheme, _ => { });
                    services.AddAuthorization(o => o.AddPolicy(
                        ContribIntuneExtensions.SyncPolicyName,
                        p => p.RequireAuthenticatedUser().RequireRole(SyncRole)));
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
                            []));
                    services.AddScepServer(new ScepServerOptions { RaCertificate = ra, DefaultProfile = "rsa" });
                    services.AddIntune(options, http => http.ConfigurePrimaryHttpMessageHandler(() => fake));
                })
                .Configure(app => app
                    .UseRouting()
                    .UseAuthentication()
                    .UseAuthorization()
                    .UseEndpoints(e =>
                    {
                        e.MapScepServer();
                        e.MapIntuneSync();
                    })))
            .Build();
        host.Start();
        return (host, rsaCa, ra);
    }

    private static void AddCaExtensions(CertificateRequest request)
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
    }

    /// <summary>Authenticates a request that carries <c>X-Test-Role</c>, with that role. Enough to prove the policy bites.</summary>
    private sealed class HeaderRoleHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("X-Test-Role", out var role))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, "caller"), new Claim(ClaimTypes.Role, role.ToString())], Scheme.Name);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
        }
    }
}
