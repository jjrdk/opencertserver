using System.Net.Security;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Data;
using OpenCertServer.Data.MsSql;
using OpenCertServer.Data.PostgreSql;
using OpenCertServer.Est.Server;
using OpenCertServer.Host.Ca;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

// Hardened certificate-authority appliance. It hosts the CA core, the EST server, and the CA-side RA
// bindings, with relational (PostgreSQL/MSSQL) or in-memory storage selected at runtime. It intentionally
// never hosts ACME or SCEP: this host is the trust anchor only.
var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;
configuration.AddEnvironmentVariables();
var appliance = ApplianceOptions.Read(configuration);

// The identity provider that guards operator access. EST client certificates also authenticate through
// the CA; a token is only required for the CA's operator endpoints. When no JWT authority is configured
// the CA runs without operator JWT (EST / mTLS continue to work), mirroring the monolith's fallback.
var authority = configuration["Jwt:Authority"] ?? configuration["authority"];
var audiences = configuration.GetSection("Jwt:Audiences").GetChildren()
    .Select(value => value.Value).OfType<string>().Where(value => !string.IsNullOrWhiteSpace(value)).ToArray();
if (audiences.Length == 0)
{
    audiences = ListConfigValues(configuration.GetSection("audience")).ToArray();
}
var jwtConfigured = Uri.TryCreate(authority, UriKind.Absolute, out var authorityUri)
    && authorityUri.Scheme == "https"
    && audiences.Length > 0;
if (!jwtConfigured && authority != null)
    throw new InvalidOperationException("Jwt:Authority must be an HTTPS identity provider when configured.");

await AddCaCore(builder.Services, configuration, args, appliance.Hardened).ConfigureAwait(false);
if (configuration["Ca:Persistence"]?.ToLowerInvariant() != "relational")
{
    builder.Services.AddInMemoryCertificateStore();
}

var auth = builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultScheme = "CaAuthentication";
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddPolicyScheme("CaAuthentication", null, options =>
    {
        options.ForwardDefaultSelector = context =>
            context.Request.Headers.Authorization.ToString()
                .StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? JwtBearerDefaults.AuthenticationScheme
                : CertificateAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCertificate();

if (jwtConfigured)
{
    auth.AddJwtBearer();
    builder.Services
        .AddSingleton(new JwtParameters { Authority = authority!, Audiences = audiences })
        .ConfigureOptions<ConfigureJwtBearerOptions>()
        .ConfigureOptions<ConfigureCertificateAuthenticationOptions>()
        .AddCertificateAuthorityAuthorization(policy => policy.AddAuthenticationSchemes(
            JwtBearerDefaults.AuthenticationScheme,
            CertificateAuthenticationDefaults.AuthenticationScheme))
        .AddHealthChecks();
}
else
{
    builder.Services
        .ConfigureOptions<ConfigureCertificateAuthenticationOptions>()
        .AddCertificateAuthorityAuthorization(policy => policy.AddAuthenticationSchemes(
            CertificateAuthenticationDefaults.AuthenticationScheme))
        .AddHealthChecks();
}

builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(180);
    options.ExcludedHosts.Clear();
});
builder.Services.AddHostFiltering(options =>
{
    options.AllowedHosts = (configuration["AllowedHosts"] ?? "localhost")
        .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    options.AllowEmptyHosts = false;
    options.IncludeFailureMessage = false;
});

// The relational engine (postgres or mssql) is chosen by Appliance:Engine so the same image can target
// either backend; the connection is read from ConnectionStrings:OpenCertServer. Schema migrations are an
// out-of-band step - never applied at start-up.
var relationalEngine =
    configuration["Appliance:Engine"]?.Trim().ToLowerInvariant();
switch (configuration["Ca:Persistence"]?.ToLowerInvariant())
{
    case null:
    case "memory":
        break;
    case "relational":
        AddRelationalEngine(builder.Services, relationalEngine)
            .AddCaRelationalStore(configuration, "OpenCertServer");
        break;
    default:
        throw new InvalidOperationException("Unsupported Ca:Persistence.");
}

RegisterTelemetry(builder.Services, configuration);

builder.WebHost.UseKestrel(options =>
    {
        options.AddServerHeader = false;
        options.ConfigureHttpsDefaults(httpsOptions =>
        {
            httpsOptions.SslProtocols = appliance.Protocols;
            httpsOptions.OnAuthenticate = (_, authentication) =>
                authentication.EnabledSslProtocols = appliance.Protocols;
            if (OperatingSystem.IsLinux())
            {
                var cipherPolicy = new CipherSuitesPolicy(
                [
                    TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                ]);
                httpsOptions.OnAuthenticate = (_, authentication) =>
                {
                    authentication.EnabledSslProtocols = appliance.Protocols;
                    authentication.CipherSuitesPolicy = cipherPolicy;
                };
            }

            httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
            httpsOptions.AllowAnyClientCertificate();
        });
    })
    .UseUrls($"https://*:{configuration.GetValue("port", 5001)}");
var certificateForwardingEnabled = ConfigureCertificateForwarding(builder.Services, configuration);
var app = builder.Build();
if (certificateForwardingEnabled)
{
    app.UseTrustedCertificateForwarding();
}

if (!OperatingSystem.IsLinux())
{
    app.Logger.LogWarning(
        "The TLS cipher allow-list requires Linux/OpenSSL; this host uses the operating system cipher policy");
}

if (appliance.Hardened)
{
    app.Use(next => context =>
    {
        context.Request.Headers.Remove("X-Client-Cert");
        return next(context);
    });
}

app.UseHsts()
    .UseHostFiltering()
    .UseHttpsRedirection()
    .UseHealthChecks("/health")
    .UseRouting()
    .Use(next => async context =>
    {
        if (!appliance.Hardened)
        {
            await next(context);
            return;
        }

        context.Response.OnCompleted(() =>
        {
            app.Logger.LogWarning("Appliance audit {TraceId} {Method} {Path} {StatusCode} {Authenticated}",
                context.TraceIdentifier, context.Request.Method, context.Request.Path,
                context.Response.StatusCode, context.User.Identity?.IsAuthenticated == true);
            return Task.CompletedTask;
        });
        await next(context);
    })
    .UseAuthentication()
    .UseAuthorization();
app.UseCertificateAuthorityServer();
await app.RunAsync().ConfigureAwait(false);
return;

// The certificate authority: with a distinguished name a self-signed CA is created at start-up; otherwise
// the configured profiles and their trust anchors are used, exactly as the monolith does.
static async Task AddCaCore(IServiceCollection services, IConfiguration configuration, string[] args,
    bool hardened)
{
    services.AddRa(configuration);
    var dn = configuration.GetSection("dn");
    var ocspUrls = ListConfigValues(configuration.GetSection("ocspUrls"));
    var crlUrls = ListConfigValues(configuration.GetSection("crlUrls"));
    var caIssuerUrls = ListConfigValues(configuration.GetSection("caIssuerUrls"));
    if (ocspUrls.Count == 0)
    {
        ocspUrls.Add("http://localhost:6001/ocsp");
    }

    if (dn.Value is not null)
    {
        services
            .AddSelfSignedCertificateAuthority(
                new X500DistinguishedName(dn.Value.StartsWith("CN=") ? dn.Value : $"CN={dn.Value}"),
                ocspUrls.ToArray(),
                crlUrls.ToArray(),
                caIssuerUrls.ToArray(),
                TimeSpan.FromDays(90))
            .AddEstServer<ConfiguredCsrTemplateLoader>();
    }
    else
    {
        var rsaProfile = await CreateProfile(args, configuration, "rsa", "--rsa", "--rsa-key",
            "--rsa-published", cert => cert.GetRSAPrivateKey()).ConfigureAwait(false);
        var ecdsaProfile = await CreateProfile(args, configuration, "ecdsa", "--ec", "--ec-key",
            "--ec-published", cert => cert.GetECDsaPrivateKey()).ConfigureAwait(false);
        services
            .AddCertificateAuthority(
                new CaConfiguration(
                    new CaProfileSet("rsa", rsaProfile, ecdsaProfile),
                    ocspUrls.ToArray(),
                    crlUrls.ToArray(),
                    caIssuerUrls.ToArray(),
                    strictOcspHttpBinding: hardened))
            .AddEstServer<ConfiguredCsrTemplateLoader>();
    }
}

static IServiceCollection AddRelationalEngine(IServiceCollection services, string? engine)
    => engine switch
    {
        null or "postgres" or "postgresql" => services.AddPostgreSqlStore(),
        "mssql" or "sqlserver" => services.AddMsSqlStore(),
        var other => throw new InvalidOperationException(
            $"Unsupported Appliance:Engine '{other}'. Expected 'postgres' or 'mssql'.")
    };

static List<string> ListConfigValues(IConfigurationSection section)
{
    var values = section.GetChildren()
        .Select(child => child.Value)
        .OfType<string>()
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .ToList();
    if (values.Count == 0 && section.Value is { } lone)
    {
        values.AddRange(lone.Split([',', ';', ' ', '\t', '\n'],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    return values;
}

static bool ConfigureCertificateForwarding(
    IServiceCollection services,
    IConfiguration configuration)
{
    var section = configuration.GetSection("CertificateForwarding");
    if (!section.GetValue<bool>("Enabled"))
    {
        return false;
    }

    var header = section["CertificateHeader"]
     ?? throw new InvalidOperationException(
            "CertificateForwarding:CertificateHeader is required when forwarding is enabled.");
    services.AddTrustedCertificateForwarding(header, options =>
    {
        foreach (var address in ListConfigValues(section.GetSection("KnownProxies")))
        {
            options.KnownProxies.Add(System.Net.IPAddress.Parse(address));
        }

        foreach (var network in ListConfigValues(section.GetSection("KnownNetworks")))
        {
            options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network));
        }
    });
    return true;
}

static async Task<CaProfile> CreateProfile(
    string[] args,
    IConfiguration configuration,
    string profileName,
    string certArgument,
    string keyArgument,
    string publishedArgument,
    Func<X509Certificate2, AsymmetricAlgorithm?> getPrivateKey)
{
    using var certificate = await CreateCert(args, configuration, profileName, certArgument, keyArgument)
        .ConfigureAwait(false);
    var privateKey = getPrivateKey(certificate)
     ?? throw new InvalidOperationException(
            $"The certificate configured for profile '{profileName}' does not expose a compatible private key.");
    using var activeCertificate = X509Certificate2.CreateFromPem(certificate.ExportCertificatePem());
    var publishedCertificatePath =
        GetArgumentValue(args, publishedArgument) ?? configuration[$"{profileName}:PublishedPem"];

    var activeCertificatePath = GetArgumentValue(args, certArgument) ?? configuration[$"{profileName}:Pem"];

    return new CaProfile
    {
        Name = profileName,
        CertificateChain = await LoadCertificateBundle(
            activeCertificatePath, activeCertificate).ConfigureAwait(false),
        PublishedCertificateChain = await LoadCertificateBundle(publishedCertificatePath, activeCertificate)
            .ConfigureAwait(false),
        CertificateValidity = TimeSpan.FromDays(90),
        CrlNumber = BigInteger.Zero,
        PrivateKey = privateKey,
        AllowPublicEnrollment =
            bool.TryParse(configuration[$"{profileName}:AllowPublicEnrollment"], out var allowPublicEnrollment)
            && allowPublicEnrollment,
        CertificatePolicies = ReadList(configuration, $"{profileName}:CertificatePolicies") ?? [],
        KeyUsage = ReadKeyUsage(configuration[$"{profileName}:KeyUsage"]),
        ExtendedKeyUsages = ReadList(configuration, $"{profileName}:ExtendedKeyUsages"),
        TrustAnchors = ReadProfileCaCertificates(configuration, $"{profileName}:TrustAnchors"),
        AdditionalChainCertificates = ReadProfileCaCertificates(
            configuration, $"{profileName}:AdditionalChainCertificates")
    };
}

static X509Certificate2Collection ReadProfileCaCertificates(IConfiguration configuration, string key)
{
    var section = configuration.GetSection(key);
    var paths = section.GetChildren().Select(child => child.Value).OfType<string>().ToArray();
    if (paths.Length == 0 && section.Value is { } path)
    {
        paths = [path];
    }

    X509Certificate2Collection certificates = [];
    foreach (var certificatePath in paths)
    {
        X509Certificate2Collection imported = [];
        imported.ImportFromPem(File.ReadAllText(certificatePath));
        if (imported.Count == 0)
        {
            throw new InvalidOperationException(
                $"CA profile setting '{key}' file '{certificatePath}' contains no PEM certificates.");
        }

        foreach (var certificate in imported)
        {
            certificate.ValidateCertificateAuthority();
            AddUniqueCertificate(certificates, certificate);
        }
    }

    return certificates;
}

static IReadOnlyList<string>? ReadList(IConfiguration configuration, string key)
{
    var section = configuration.GetSection(key);
    var children = section.GetChildren().Select(c => c.Value).OfType<string>().ToArray();
    if (children.Length > 0)
    {
        return children;
    }

    return section.Value is { } value
        ? value.Split([',', ';', ' ', '\t', '\n'],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        : null;
}

static X509KeyUsageFlags? ReadKeyUsage(string? value)
{
    return string.IsNullOrWhiteSpace(value)
        ? null
        : Enum.Parse<X509KeyUsageFlags>(value, ignoreCase: true);
}

static string? GetArgumentValue(string[] args, string argumentName)
{
    var index = Array.IndexOf(args, argumentName);
    return index >= 0 && index + 1 < args.Length
        ? args[index + 1]
        : null;
}

static async Task<X509Certificate2Collection> LoadCertificateBundle(
    string? certificateBundlePath,
    X509Certificate2 activeCertificate)
{
    if (string.IsNullOrWhiteSpace(certificateBundlePath))
    {
        return [];
    }

    var pem = await File.ReadAllTextAsync(certificateBundlePath).ConfigureAwait(false);
    X509Certificate2Collection importedCertificates = [];
    importedCertificates.ImportFromPem(pem);
    if (importedCertificates.Count == 0)
    {
        throw new InvalidOperationException(
            $"The CA certificate bundle '{certificateBundlePath}' did not contain any PEM certificates.");
    }

    X509Certificate2Collection publishedCertificates = [];
    AddUniqueCertificate(publishedCertificates,
        X509Certificate2.CreateFromPem(activeCertificate.ExportCertificatePem()));
    foreach (var certificate in importedCertificates)
    {
        AddUniqueCertificate(publishedCertificates, certificate);
    }

    return publishedCertificates;
}

static void AddUniqueCertificate(
    X509Certificate2Collection collection,
    X509Certificate2 certificate)
{
    if (collection.Any(existing =>
        string.Equals(existing.Thumbprint, certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)))
    {
        certificate.Dispose();
        return;
    }

    collection.Add(certificate);
}

static async Task<X509Certificate2> CreateCert(
    string[] args,
    IConfiguration configuration,
    string profileName,
    string cert,
    string certKey)
{
    var path = GetArgumentValue(args, cert) ?? configuration[$"{profileName}:Pem"]
     ?? throw new InvalidOperationException($"Set {profileName}:Pem or {cert} to a CA certificate file.");
    var key = GetArgumentValue(args, certKey) ?? configuration[$"{profileName}:KeyPem"];
    using var file = File.OpenText(path);
    using var keyFile = key == null ? TextReader.Null : File.OpenText(key);
    var pem = await file.ReadToEndAsync().ConfigureAwait(false);
    var keyPem = await keyFile.ReadToEndAsync().ConfigureAwait(false);
    var x509 = key == null
        ? X509Certificate2.CreateFromPem(pem)
        : X509Certificate2.CreateFromPem(pem, keyPem);
    return x509;
}

static IServiceCollection RegisterTelemetry(IServiceCollection services, IConfiguration configuration)
{
    var telemetry = configuration.GetSection("Telemetry");
    if (!string.Equals(telemetry["Enabled"], "true", StringComparison.OrdinalIgnoreCase))
    {
        return services;
    }

    var otlpEndpoint = telemetry["OtlpEndpoint"] ?? "http://localhost:4317";
    var endpoint = new Uri(otlpEndpoint, UriKind.Absolute);
    var serviceName = telemetry["ServiceName"] ?? "opencertserver";

    services
        .AddOpenTelemetry()
        .ConfigureResource(builder => builder
            .AddService(serviceName: serviceName)
            .AddTelemetrySdk())
        .WithMetrics(meter =>
        {
            meter
                .AddMeter("opencertserver.est")
                .AddMeter("opencertserver.ca")
                .AddMeter("opencertserver.ca.core")
                .AddMeter("opencertserver.ca.client")
                .AddMeter("opencertserver.data")
                .AddMeter("opencertserver.data.postgresql")
                .AddMeter("opencertserver.data.mssql")
                .AddOtlpExporter(options => options.Endpoint = endpoint);
        })
        .WithTracing(tracer =>
        {
            tracer
                .AddSource("opencertserver.est")
                .AddSource("opencertserver.ca")
                .AddSource("opencertserver.ca.core")
                .AddSource("opencertserver.ca.client")
                .AddSource("opencertserver.data")
                .AddSource("opencertserver.data.postgresql")
                .AddSource("opencertserver.data.mssql")
                .AddOtlpExporter(options => options.Endpoint = endpoint);
        });

    return services;
}

namespace OpenCertServer.Host.Ca
{
    /// <summary>Appliance hardening flags read from configuration.</summary>
    internal sealed record ApplianceOptions(bool Hardened, string? DataDirectory)
    {
        public System.Security.Authentication.SslProtocols Protocols =>
            Hardened ? System.Security.Authentication.SslProtocols.Tls13
                : System.Security.Authentication.SslProtocols.Tls12 |
                System.Security.Authentication.SslProtocols.Tls13;

        public static ApplianceOptions Read(IConfiguration configuration)
        {
            var section = configuration.GetSection("Appliance");
            var hardened = section["Hardened"] is not { } raw ||
                bool.TryParse(raw, out var value) && value;
            return new ApplianceOptions(hardened, section["DataDirectory"]);
        }
    }
}
