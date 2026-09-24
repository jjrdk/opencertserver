namespace OpenCertServer.Mcp.Tests.Support;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.ComponentModel;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Ca;
using Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using Ca.Utils.Ocsp;
using OpenCertServer.Mcp.Tools;
using ModelContextProtocol.Server;
using Microsoft.Extensions.Options;

public class McpServerFixture : IDisposable
{
    private readonly IHost _host;
    public IReadOnlyDictionary<string, McpToolDefinition> ToolDefinitions { get; }
    public CertificateAuthority CertificateAuthority { get; }
    public IStoreCertificates Store { get; }
    private readonly List<X509Certificate2> _issuedCerts = new();

    public McpServerFixture()
    {
        var loggerFactory = LoggerFactory.Create(builder => { });
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

        _host = Host.CreateDefaultBuilder()
            .ConfigureServices((_, services) =>
            {
                services.Configure<OpenCertServer.Mcp.McpServerOptions>(o =>
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
            })
            .Build();
        _host.Start();

        var resolved = _host.Services.GetRequiredService<IStoreCertificates>();
        CertificateAuthority = certAuthority;
        Store = resolved;
        ToolDefinitions = BuildToolDefinitions();
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
        var result = await CertificateAuthority.SignCertificateRequestPem(pemCsr, "rsa").ConfigureAwait(false);
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
        return (await CreateAndSignCertificate(cn).ConfigureAwait(false)).cert;
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

    public async Task<McpToolResult> InvokeMcpToolAsync(string toolName, object parameters)
    {
        var dict = ConvertToDict(parameters);
        var services = _host.Services;
        var cancellationToken = CancellationToken.None;

        try
        {
            object result = toolName switch
            {
                "get_server_metadata" => await GetServerMetadataTool.GetServerMetadata(
                    services.GetRequiredService<CaConfiguration>(),
                    services.GetRequiredService<IStoreCaProfiles>(),
                    services.GetRequiredService<IOptions<OpenCertServer.Mcp.McpServerOptions>>(),
                    cancellationToken).ConfigureAwait(false),
                "list_certificates" => await ListCertificatesTool.ListCertificatesAsync(
                    services.GetRequiredService<IStoreCertificates>(),
                    GetInt32(dict, "page", 0),
                    GetInt32(dict, "pageSize", 100),
                    cancellationToken).ConfigureAwait(false),
                "search_certificates" => await SearchCertificatesTool.SearchCertificates(
                    services.GetRequiredService<IStoreCertificates>(),
                    GetString(dict, "subjectCN"),
                    GetString(dict, "subjectContains"),
                    GetString(dict, "issuerContains"),
                    GetString(dict, "serialNumber"),
                    GetString(dict, "thumbprint"),
                    GetDateTimeOffset(dict, "notBeforeAfter"),
                    GetDateTimeOffset(dict, "notBeforeBefore"),
                    GetDateTimeOffset(dict, "notAfterAfter"),
                    GetDateTimeOffset(dict, "notAfterBefore"),
                    GetString(dict, "status"),
                    GetStringArray(dict, "keyAlgorithms"),
                    GetInt32(dict, "page", 0),
                    GetInt32(dict, "pageSize", 100),
                    cancellationToken).ConfigureAwait(false),
                "get_certificate" => await GetCertificateTool.GetCertificate(
                    services.GetRequiredService<IStoreCertificates>(),
                    GetString(dict, "serialNumber") ?? string.Empty,
                    GetBoolean(dict, "includePem", false),
                    cancellationToken).ConfigureAwait(false),
                "get_ca_certificates" => await GetCaCertificatesTool.GetCaCertificates(
                    services.GetRequiredService<ICertificateAuthority>(),
                    GetString(dict, "profileName"),
                    GetBoolean(dict, "includeFullChain", false),
                    cancellationToken).ConfigureAwait(false),
                "sign_certificate" => await SignCertificateTool.SignCertificate(
                    services.GetRequiredService<ICertificateAuthority>(),
                    GetString(dict, "csr") ?? string.Empty,
                    GetString(dict, "profileName"),
                    GetDateTimeOffset(dict, "notBefore"),
                    GetDateTimeOffset(dict, "notAfter"),
                    GetBoolean(dict, "includePem", false),
                    cancellationToken).ConfigureAwait(false),
                "revoke_certificate" => await RevokeCertificateTool.RevokeCertificate(
                    services.GetRequiredService<ICertificateAuthority>(),
                    GetString(dict, "serialNumber") ?? string.Empty,
                    GetString(dict, "reason") ?? "Unspecified",
                    cancellationToken).ConfigureAwait(false),
                "get_revocation_status" => await GetRevocationStatusTool.GetRevocationStatus(
                    services.GetRequiredService<IStoreCertificates>(),
                    GetStringArray(dict, "serialNumbers") ?? Array.Empty<string>(),
                    GetString(dict, "profileName"),
                    cancellationToken).ConfigureAwait(false),
                "check_ocsp_status" => await CheckOcspStatusTool.CheckOcspStatus(
                    services.GetRequiredService<IStoreCertificates>(),
                    GetString(dict, "serialNumber") ?? string.Empty,
                    GetString(dict, "issuerNameHash") ?? string.Empty,
                    GetString(dict, "issuerKeyHash") ?? string.Empty,
                    cancellationToken).ConfigureAwait(false),
                "get_crl" => await GetCrlTool.GetCrl(
                    services.GetRequiredService<ICertificateAuthority>(),
                    GetString(dict, "profileName"),
                    GetBoolean(dict, "includePem", false),
                    cancellationToken).ConfigureAwait(false),
                _ => throw new UnknownToolException(toolName)
            };

            return McpToolResult.Ok(result);
        }
        catch (UnknownToolException)
        {
            return McpToolResult.Fail($"Tool not found: {toolName}", (int)McpErrorCode.ToolNotFound);
        }
        catch (Exception ex)
        {
            return McpToolResult.Fail(ex.Message);
        }
    }

    private static Dictionary<string, object> ConvertToDict(object obj)
    {
        if (obj is IDictionary<string, object> existing)
        {
            return new Dictionary<string, object>(existing);
        }

        var dict = new Dictionary<string, object>();
#pragma warning disable IL2075
        foreach (var prop in obj.GetType().GetProperties(
                     System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance))
#pragma warning restore IL2075
        {
            var val = prop.GetValue(obj);
            if (val != null)
            {
                dict[prop.Name] = val;
            }
        }
        return dict;
    }

    private static IReadOnlyDictionary<string, McpToolDefinition> BuildToolDefinitions()
    {
        var toolMethods = typeof(GetServerMetadataTool).Assembly
            .GetTypes()
            .Where(t => t.GetCustomAttributes(typeof(McpServerToolTypeAttribute), inherit: false).Any())
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Static))
            .Select(m => new
            {
                Method = m,
                Attribute = m.GetCustomAttribute<McpServerToolAttribute>(),
                Description = m.GetCustomAttribute<DescriptionAttribute>()?.Description ?? string.Empty
            })
            .Where(x => x.Attribute != null)
            .ToDictionary(
                x => x.Attribute!.Name ?? x.Method.Name,
                x => new McpToolDefinition
                {
                    Name = x.Attribute!.Name ?? x.Method.Name,
                    Description = x.Description,
                    InputSchema = "{\"type\":\"object\",\"properties\":{}}"
                },
                StringComparer.Ordinal);

        return toolMethods;
    }

    private static string? GetString(IDictionary<string, object> parameters, string key)
    {
        if (!parameters.TryGetValue(key, out var value) || value == null)
        {
            return null;
        }

        return value is JsonElement element && element.ValueKind == JsonValueKind.String
            ? element.GetString()
            : value.ToString();
    }

    private static int GetInt32(IDictionary<string, object> parameters, string key, int defaultValue)
    {
        if (!parameters.TryGetValue(key, out var value) || value == null)
        {
            return defaultValue;
        }

        if (value is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var i))
            {
                return i;
            }

            if (element.ValueKind == JsonValueKind.String && int.TryParse(element.GetString(), out var parsed))
            {
                return parsed;
            }
        }

        if (value is int intValue)
        {
            return intValue;
        }

        return int.TryParse(value.ToString(), out var result) ? result : defaultValue;
    }

    private static bool GetBoolean(IDictionary<string, object> parameters, string key, bool defaultValue)
    {
        if (!parameters.TryGetValue(key, out var value) || value == null)
        {
            return defaultValue;
        }

        if (value is JsonElement element)
        {
            if (element.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                return element.GetBoolean();
            }

            if (element.ValueKind == JsonValueKind.String && bool.TryParse(element.GetString(), out var parsed))
            {
                return parsed;
            }
        }

        if (value is bool boolValue)
        {
            return boolValue;
        }

        return bool.TryParse(value.ToString(), out var result) ? result : defaultValue;
    }

    private static DateTimeOffset? GetDateTimeOffset(IDictionary<string, object> parameters, string key)
    {
        if (!parameters.TryGetValue(key, out var value) || value == null)
        {
            return null;
        }

        if (value is DateTimeOffset dto)
        {
            return dto;
        }

        if (value is JsonElement element && element.ValueKind == JsonValueKind.String &&
            DateTimeOffset.TryParse(element.GetString(), out var parsedElement))
        {
            return parsedElement;
        }

        return DateTimeOffset.TryParse(value.ToString(), out var parsed) ? parsed : null;
    }

    private static string[]? GetStringArray(IDictionary<string, object> parameters, string key)
    {
        if (!parameters.TryGetValue(key, out var value) || value == null)
        {
            return null;
        }

        if (value is string[] stringArray)
        {
            return stringArray;
        }

        if (value is IEnumerable<string> enumerable)
        {
            return enumerable.ToArray();
        }

        if (value is JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                return element.EnumerateArray()
                    .Select(item => item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString())
                    .Where(item => !string.IsNullOrWhiteSpace(item))
                    .Cast<string>()
                    .ToArray();
            }

            if (element.ValueKind == JsonValueKind.String)
            {
                return element.GetString()?.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            }
        }

        if (value is IEnumerable<object> objects)
        {
            return objects.Select(o => o.ToString()).Where(s => !string.IsNullOrWhiteSpace(s)).Cast<string>().ToArray();
        }

        if (value is string s)
        {
            return s.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        }

        return null;
    }

    public void Dispose()
    {
        _host?.Dispose();
        foreach (var cert in _issuedCerts)
            cert.Dispose();
    }
}

internal sealed class UnknownToolException(string toolName) : Exception($"Tool not found: {toolName}");

/// <summary>
/// A null chain validator that always passes - used for testing.
/// </summary>
internal class NullChainValidator : IValidateX509Chains
{
    public Task<bool> Validate(X509Chain chain, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(true);
    }
}
