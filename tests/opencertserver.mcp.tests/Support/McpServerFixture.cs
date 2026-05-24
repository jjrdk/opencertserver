namespace OpenCertServer.Mcp.Tests.Support;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Ca.Server;
using OpenCertServer.Mcp;
using Microsoft.Extensions.Options;

public class McpServerFixture : IDisposable
{
    private readonly IHost _host;
    public McpServer McpServer { get; }
    public CertificateAuthority CertificateAuthority { get; }
    public IStoreCertificates Store { get; }
    private readonly List<X509Certificate2> _issuedCerts = new();

    public McpServerFixture()
     {
        var loggerFactory = LoggerFactory.Create(builder => { });
        var mcpLogger = loggerFactory.CreateLogger<McpServer>();
        var caLogger = loggerFactory.CreateLogger<CertificateAuthority>();
        var store = new InMemoryCertificateStore();

        var caConfig = new CaConfiguration(
            new CaProfileSet("rsa",
                CertificateAuthority.CreateSelfSignedRsa(
                     "rsa",
                    new X500DistinguishedName("CN=MCP Test CA"),
                    TimeSpan.FromDays(365)),
                CertificateAuthority.CreateSelfSignedEcdsa(
                     "ecdsa",
                    new X500DistinguishedName("CN=MCP Test CA ECDSA"),
                    TimeSpan.FromDays(365))),
             [], [], [], false);

        var certAuthority = new CertificateAuthority(
            caConfig,
            store,
            new NullChainValidator(),
            caLogger);

        var mcpServer = new McpServer(
            new McpServerOptions { ServerName = "TestMcpServer", ServerVersion = "1.0.0" }, mcpLogger);
        mcpServer.RegisterAll();

         _host = Host.CreateDefaultBuilder()
             .ConfigureServices((_, services) =>
             {
                services.Configure<McpServerOptions>(o =>
                {
                    o.ServerName = "TestMcpServer";
                    o.ServerVersion = "1.0.0";
                });
                services.AddSingleton(caConfig);
                services.AddSingleton<IStoreCertificates>(store);
                services.AddSingleton<IStoreCaProfiles>(caConfig.Profiles);
                services.AddSingleton<ICertificateAuthority>(certAuthority);
                services.AddSingleton<CertificateAuthority>(certAuthority);
                services.AddSingleton<IResponderId>(new ResponderIdByKey(RSA.Create(2048)!.ExportSubjectPublicKeyInfo()));
                services.AddSingleton(mcpServer);
             })
             .Build();
         _host.Start();

        var resolved = _host.Services.GetRequiredService<IStoreCertificates>();
        var resolvedMcp = _host.Services.GetRequiredService<McpServer>();

        McpServer = resolvedMcp;
        CertificateAuthority = certAuthority;
        Store = resolved;

        McpServer.InitializeAsync(_host.Services).GetAwaiter().GetResult();
     }

    private async Task<(string csrPem, X509Certificate2 cert)> CreateAndSignCertificate(string cn)
     {
        using var rsa = RSA.Create(3072);
        var request = new CertificateRequest(
            new X500DistinguishedName($"CN={cn}"),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        var pemCsr = request.ToPkcs10Base64();
        var result = await CertificateAuthority.SignCertificateRequestPem(pemCsr, "rsa");
        X509Certificate2 cert;
        if (result is SignCertificateResponse.Success success)
         {
           cert = success.Certificate;
           foreach (var c in success.Issuers)
                 _issuedCerts.Add(X509CertificateLoader.LoadCertificate(c.GetRawCertData()));
         }
        else
         {
            var error = (SignCertificateResponse.Error)result;
            throw new InvalidOperationException(
                 $"Signing failed: {string.Join(", ", error.Errors)}");
         }
         _issuedCerts.Add(cert);
        return (pemCsr, cert);
     }

    public async Task<X509Certificate2> CreateAndIssueCertificateAsync(string cn)
     {
        return (await CreateAndSignCertificate(cn)).cert;
     }

    public static string CreateBase64DerCsr()
     {
        using var rsa = RSA.Create();
        var request = new CertificateRequest(
            new X500DistinguishedName("CN=test"),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        return Convert.ToBase64String(request.CreateSigningRequest());
     }

    public Task<McpToolResult> InvokeMcpToolAsync(string toolName, object parameters)
     {
        var dict = ConvertToDict(parameters);
        return McpServer.InvokeTool(toolName, dict);
     }

    private static Dictionary<string, object> ConvertToDict(object obj)
     {
        if (obj is IDictionary<string, object> existing)
            return new Dictionary<string, object>(existing);
        var dict = new Dictionary<string, object>();
#pragma warning disable IL2075
        foreach (var prop in obj.GetType().GetProperties(
                     System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance))
#pragma warning restore IL2075
        {
            var val = prop.GetValue(obj);
            if (val != null)
                dict[prop.Name] = val;
        }
        return dict;
     }

    public void Dispose()
     {
         _host?.Dispose();
        McpServer?.Dispose();
        foreach (var cert in _issuedCerts)
            cert.Dispose();
     }
}

/// <summary>
/// A null chain validator that always passes - used for testing.
/// </summary>
internal class NullChainValidator : OpenCertServer.Ca.IValidateX509Chains
{
    public System.Threading.Tasks.Task<bool> Validate(System.Security.Cryptography.X509Certificates.X509Chain chain, System.Threading.CancellationToken cancellationToken = default)
    {
        return System.Threading.Tasks.Task.FromResult(true);
    }
}
