using System.Runtime.CompilerServices;
using OpenCertServer.Est.Server.TrustAnchor;
using OpenCertServer.Data;
using OpenCertServer.Data.PostgreSql;

[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]

namespace OpenCertServer.CertServer;

using System.Security.Cryptography;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using System.Linq;
using System.Numerics;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Acme.Abstractions.IssuanceServices;
using Est.Server;
using Est.Server.BasicAuthentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Acme.Server;
using Acme.Server.Extensions;
using Acme.Server.Services;
using Acme.Abstractions.Storage;
using Acme.Abstractions.Model;
using Acme.Abstractions.Services;
using Ca;
using Ca.Server;
using CertServer.Stores;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Contrib.Intune;
using Scep.Server;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            throw new Exception("No configuration values passed");
        }

        var builder = WebApplication.CreateBuilder(args);
        builder.Configuration.AddEnvironmentVariables().AddCommandLine(args);
        var services = builder.Services
            .AddCors(options =>
            {
                options.AddPolicy("TrustedClients", pb =>
                {
                    pb
                        .WithOrigins(
                            builder
                                .Configuration.GetSection("Cors:TrustedOrigins")
                                .GetChildren()
                                .Select(origin => origin.Value)
                                .OfType<string>()
                                .ToArray())
                        .AllowCredentials()
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            })
            .AddInMemoryCertificateStore();
        var port = int.TryParse(builder.Configuration.GetSection("port").Value, out var p)
            ? p
            : 5001; //portIndex >= 0 ? int.Parse(args[portIndex + 1]) : 5001;
        var index = 0;
        List<string> ocspUrls = [];
        List<string> caIssuerUrls = [];
        List<string> crlUrls = [];

        // Seed the authority information access (AIA) and CRL distribution point (CDP) defaults from
        // configuration so that, in a hardened deployment, every issued certificate names the responder
        // URLs of this server (OCSP, AIA caIssuers, CRL distribution point). Command-line values still
        // append, and the localhost development default still applies when neither source supplies OCSP.
        caIssuerUrls.AddRange(ListConfigValues(builder.Configuration.GetSection("CaServer:CaIssuers")));
        crlUrls.AddRange(ListConfigValues(builder.Configuration.GetSection("CaServer:CrlDistributionPoints")));
        var configuredOcsp = ListConfigValues(builder.Configuration.GetSection("CaServer:OCSP"));
        if (configuredOcsp.Count > 0)
        {
            ocspUrls = configuredOcsp;
        }

        while (index >= 0)
        {
            index = Array.IndexOf(args, "--ocsp", index);
            if (index < 0)
            {
                continue;
            }

            ocspUrls.Add(args[index + 1]);
            index++;
        }

        if (ocspUrls.Count == 0)
        {
            // The development default. It used to be the first entry whatever --ocsp said, so every
            // issued certificate pointed relying parties at localhost:6001 before the real responder.
            ocspUrls.Add("http://localhost:6001/ocsp");
        }

        index = 0;
        while (index >= 0)
        {
            index = Array.IndexOf(args, "--ca-issuer", index);
            if (index < 0)
            {
                continue;
            }

            caIssuerUrls.Add(args[index + 1]);
            index++;
        }

        index = 0;
        while (index >= 0)
        {
            index = Array.IndexOf(args, "--crl", index);
            if (index < 0)
            {
                continue;
            }

            if (index + 1 < args.Length)
            {
                crlUrls.Add(args[index + 1]);
            }

            index++;
        }

        var dn = builder.Configuration.GetSection("dn");
        if (dn.Value is not null)
        {
            services = services.AddSelfSignedCertificateAuthority(
                    new X500DistinguishedName(
                        dn.Value.StartsWith("CN=") ? dn.Value : $"CN={dn.Value}"),
                    ocspUrls.ToArray(),
                    crlUrls.ToArray(),
                    caIssuerUrls.ToArray(),
                    TimeSpan.FromDays(90))
                .AddEstServer<ConfiguredCsrTemplateLoader>();
        }
        else
        {
            var rsaProfile = await CreateProfile(
                args,
                builder.Configuration,
                profileName: "rsa",
                certArgument: "--rsa",
                keyArgument: "--rsa-key",
                publishedArgument: "--rsa-published",
                getPrivateKey: cert => cert.GetRSAPrivateKey()).ConfigureAwait(false);
            var ecdsaProfile = await CreateProfile(
                args,
                builder.Configuration,
                profileName: "ecdsa",
                certArgument: "--ec",
                keyArgument: "--ec-key",
                publishedArgument: "--ec-published",
                getPrivateKey: cert => cert.GetECDsaPrivateKey()).ConfigureAwait(false);
            services = services
                .AddCertificateAuthority(
                    new CaConfiguration(
                        new CaProfileSet("rsa", rsaProfile, ecdsaProfile),
                        ocspUrls.ToArray(),
                        crlUrls.ToArray(),
                        caIssuerUrls.ToArray()))
                .AddEstServer<ConfiguredCsrTemplateLoader>();
        }

        services = services.AddEstTrustAnchors(options => ReadEstTrustAnchors(builder.Configuration, options));
        services = await AddScep(services, args, builder.Configuration).ConfigureAwait(false);

        var a = Array.IndexOf(args, "--authority");
        var authority = a >= 0
            ? args[a + 1]
            : throw new Exception("No authority specified. Use --authority <url> to specify the authority URL.");

        var aud = Array.IndexOf(args, "--audience");
        var audiences = aud >= 0
            ? args[aud + 1].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : throw new Exception("No audience specified. Use --audience <url> to specify the audience URL.");

        var forwardedHeadersOptions = CreateForwardedHeaderOptions();
        const string caAuthenticationScheme = "CaAuthentication";

        _ = services.AddAuthentication(options =>
            {
                options.DefaultScheme = caAuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddPolicyScheme(caAuthenticationScheme, null, options =>
            {
                options.ForwardDefaultSelector = context =>
                    context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                        ? JwtBearerDefaults.AuthenticationScheme
                        : CertificateAuthenticationDefaults.AuthenticationScheme;
            })
            .AddJwtBearer()
            .AddCertificate()
            // Certificate-authentication results are route-independent; do not cache them because
            // EST trust anchors must not authorize the same certificate on CA endpoints.
            // User name and password for EST (RFC 7030 §3.2.3): off until Est:BasicAuth:Users or
            // Est:BasicAuth:UsersFile is set. Hashes only - `opencert hash-password` makes them.
            .AddEstBasicAuthentication(options => ReadBasicAuthentication(builder.Configuration, options))
            .Services
            .AddAcmeServer(builder.Configuration)
            .AddAcmeInMemoryStore()
            .AddSingleton(new JwtParameters { Authority = authority, Audiences = audiences })
            .AddSingleton<ICsrValidator, DefaultCsrValidator>()
            .AddSingleton<IIssueCertificates, DefaultIssuer>()
            .ConfigureOptions<ConfigureJwtBearerOptions>()
            .ConfigureOptions<ConfigureCertificateAuthenticationOptions>()
            .AddAuthorization(options => options.AddPolicy(
                ContribIntuneExtensions.SyncPolicyName,
                policy => policy
                    .AddAuthenticationSchemes(
                        JwtBearerDefaults.AuthenticationScheme,
                        CertificateAuthenticationDefaults.AuthenticationScheme)
                    .RequireAuthenticatedUser()
                    .RequireRole(RevocationAuthorizationConstants.CaAdminRole)))
            .AddCertificateAuthorityAuthorization(policy => policy.AddAuthenticationSchemes(
                JwtBearerDefaults.AuthenticationScheme,
                CertificateAuthenticationDefaults.AuthenticationScheme))
            .AddHealthChecks();

        services.AddHsts(options =>
        {
            options.MaxAge = TimeSpan.FromDays(180);
            options.ExcludedHosts.Clear();
        });
        services.AddHostFiltering(options =>
        {
            options.AllowedHosts = (builder.Configuration["AllowedHosts"] ?? "localhost")
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            options.AllowEmptyHosts = false;
            options.IncludeFailureMessage = false;
        });

        // --- Hardened-deployment registrations, each config-gated and fail-closed when unset ---

        switch (builder.Configuration["AcmeServer:Persistence"]?.ToLowerInvariant())
        {
            case null:
            case "memory":
                break;
            case "file":
                services.AddAcmeFileStore(builder.Configuration);
                break;
            case "relational":
                services.AddPostgreSqlStore()
                    .AddAcmeRelationalStore(builder.Configuration, "OpenCertServer");
                break;
            default:
                throw new InvalidOperationException("Unsupported AcmeServer:Persistence.");
        }
        switch (builder.Configuration["Ca:Persistence"]?.ToLowerInvariant())
        {
            case null:
            case "memory":
                break;
            case "relational":
                services.AddPostgreSqlStore()
                    .AddCaRelationalStore(builder.Configuration, "OpenCertServer");
                break;
            default:
                throw new InvalidOperationException("Unsupported Ca:Persistence.");
        }
        // Configured EAB keys override the selected empty or relational key store.
        RegisterExternalAccountKeys(services, builder.Configuration);

        // Attestation trust roots for the device-attest-01 challenge: when configured the static trust
        // provider overrides the ACME server's empty default (which rejects every proof), enabling device
        // identity without broadening the default.
        RegisterAttestationTrustAnchors(services, builder.Configuration);

        // OpenTelemetry metrics and traces: exported over OTLP when enabled, so a deployment's
        // instrumentation (the opencertserver.acme / .est / .scep / .intune / .ca meters and activity sources)
        // is scrapeable.
        RegisterTelemetry(builder.Services, builder.Configuration);

        builder.WebHost.UseKestrel(options =>
            {
                options.AddServerHeader = false;
                options.ConfigureHttpsDefaults(httpsOptions =>
                {
                    // RFC 7030 requires TLS 1.1 or later for EST; prefer TLS 1.2+ in practice.
                    httpsOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
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
                            authentication.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                            authentication.CipherSuitesPolicy = cipherPolicy;
                        };
                    }
                    // Kestrel presents an X.509 server certificate that is expected to conform to RFC5280.
                    // Leave TLS session resumption enabled (the default) because RFC 7030 recommends session resumption support.
                    // Ask the client for a certificate: EST re-enrollment and self-service revocation
                    // authenticate with one. Kestrel only transports it; the authentication handler
                    // validates it against the CA chain and, for EST routes only, configured client anchors.
                    httpsOptions.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
                    httpsOptions.AllowAnyClientCertificate();
                });
            })
            .UseUrls($"https://*:{port}");
        var certificateForwardingEnabled = ConfigureCertificateForwarding(builder.Services, builder.Configuration);
        var app = builder.Build();
        if (certificateForwardingEnabled)
        {
            app.UseTrustedCertificateForwarding();
        }

        if (!OperatingSystem.IsLinux())
        {
            app.Logger.LogWarning("The TLS cipher allow-list requires Linux/OpenSSL; this host uses the operating system cipher policy");
        }

        app.UseHsts()
            .UseHostFiltering()
            .Use(next => context =>
            {
                // Kestrel renames Content-Length to X-Content-Length when normalizing CL+TE.
                if (!context.Request.Headers.ContainsKey("X-Content-Length") &&
                    (!context.Request.Headers.ContainsKey("Content-Length") ||
                        !context.Request.Headers.ContainsKey("Transfer-Encoding")))
                {
                    return next(context);
                }

                app.Logger.LogWarning("Rejected ambiguous request framing on connection {ConnectionId}",
                    context.Connection.Id);
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                if (context.Request.Protocol.StartsWith("HTTP/1.", StringComparison.Ordinal))
                {
                    context.Response.Headers.Connection = "close";
                }

                return Task.CompletedTask;

            })
            .UseHttpsRedirection()
            .UseCors("TrustedClients")
            .UseForwardedHeaders(forwardedHeadersOptions)
            .UseHealthChecks("/health")
            .UseRouting()
            .UseAuthentication()
            .UseAuthorization()
            .UseAcmeServer()
            .UseEstServer(
                enrollPolicy: EstPolicy(),
                reEnrollPolicy: EstPolicy(),
                serverKeyGenPolicy: EstPolicy())
            .UseCertificateAuthorityServer();
        app.MapScepServer();
        if (builder.Configuration.GetSection(IntuneOptions.SectionName).Exists())
        {
            app.MapIntuneSync();
        }

        await app.RunAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Est:BasicAuth from configuration, read by hand - the project is built for AOT, and binding a
    /// typed object needs code generated at run time.
    /// </summary>
    private static void ReadBasicAuthentication(IConfiguration configuration, EstBasicAuthenticationOptions options)
    {
        var section = configuration.GetSection("Est:BasicAuth");
        options.UsersFile = section["UsersFile"];
        options.Realm = section["Realm"] ?? options.Realm;
        foreach (var user in section.GetSection("Users").GetChildren())
        {
            if (!string.IsNullOrWhiteSpace(user.Value))
            {
                options.Users[user.Key] = user.Value;
            }
        }
    }

    private static void ReadEstTrustAnchors(IConfiguration configuration, EstTrustAnchorOptions options)
    {
        var configuredPaths = new[]
            {
                configuration.GetSection("Est:ExplicitTrustAnchors"),
                configuration.GetSection("Est:TrustedClientCerts")
            }
            .SelectMany(section =>
            {
                var values = section.GetChildren().Select(child => child.Value).OfType<string>().ToArray();
                return values.Length == 0 && section.Value is { } value ? [value] : values;
            })
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        foreach (var path in configuredPaths)
        {
            var certificates = new X509Certificate2Collection();
            certificates.ImportFromPem(File.ReadAllText(path));
            if (certificates.Count == 0)
            {
                throw new InvalidOperationException(
                    $"EST client trust-anchor file '{path}' contains no PEM certificates.");
            }

            try
            {
                for (var index = 0; index < certificates.Count - 1; index++)
                {
                    options.AdditionalChainCertificates.Add(
                        X509CertificateLoader.LoadCertificate(certificates[index].RawData));
                }

                options.TrustAnchors.Add(
                    X509CertificateLoader.LoadCertificate(certificates[^1].RawData));
            }
            finally
            {
                foreach (var certificate in certificates)
                {
                    certificate.Dispose();
                }
            }
        }
    }

    /// <summary>
    /// Who may enroll: a token, a client certificate, or - where users are configured - a user name and
    /// password. The Basic scheme is always registered, so listing it costs nothing when it is off.
    /// </summary>
    private static AuthorizationPolicy EstPolicy()
    {
        return new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(
                JwtBearerDefaults.AuthenticationScheme,
                CertificateAuthenticationDefaults.AuthenticationScheme,
                EstBasicAuthenticationDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .Build();
    }

    /// <summary>
    /// External account keys configured under <c>AcmeServer:ExternalAccountKey:{keyId}</c>, each with a
    /// <c>MacKey</c> (a base64url HMAC key) and an optional <c>MacAlgorithm</c> (default HS256). When none
    /// are configured nothing is registered and the empty in-memory store that <c>AddAcmeInMemoryStore</c>
    /// registered is retained, so EAB simply cannot bind.
    /// </summary>
    private static IServiceCollection RegisterExternalAccountKeys(IServiceCollection services, IConfiguration configuration)
    {
        var keys = configuration
            .GetSection("AcmeServer:ExternalAccountKey")
            .GetChildren()
            .Select(child => new ExternalAccountKey(
                child.Key,
                child["MacKey"] ?? throw new InvalidOperationException(
                    $"'AcmeServer:ExternalAccountKey:{child.Key}' is missing its 'MacKey'."),
                child["MacAlgorithm"] ?? "HS256"))
            .ToArray();
        if (keys.Length == 0)
        {
            return services;
        }

        // Registered after AddAcmeInMemoryStore so the static store wins resolution.
        return services.AddSingleton<IStoreExternalAccountKeys>(new StaticExternalAccountKeyStore(keys));
    }

    /// <summary>
    /// Attestation trust roots configured as PEM bundles under <c>Attestation:TrustAnchors</c> (paths).
    /// When none are configured the ACME server's empty trust provider is retained, which rejects every
    /// device-attest-01 proof - the fail-closed default for a hardened deployment.
    /// </summary>
    private static IServiceCollection RegisterAttestationTrustAnchors(IServiceCollection services, IConfiguration configuration)
    {
        var paths = ListConfigValues(configuration.GetSection("Attestation:TrustAnchors"));
        if (paths.Count == 0)
        {
            return services;
        }

        var roots = new X509Certificate2Collection();
        foreach (var path in paths)
        {
            roots.ImportFromPem(File.ReadAllText(path));
        }
        if (roots.Count == 0)
        {
            throw new InvalidOperationException(
                "The configured attestation trust anchors contain no PEM certificates; the device-attest-01 " +
                "challenge cannot authenticate any device.");
        }

        // Registered after AddAcmeServer so the static provider overrides the server's empty default.
        return services.AddSingleton<IAttestationTrustProvider>(new StaticAttestationTrustProvider(roots));
    }

    /// <summary>
    /// OpenTelemetry export over OTLP, enabled only when <c>Telemetry:Enabled</c> is set. The
    /// <c>opencertserver.acme</c>, <c>opencertserver.est</c>, <c>opencertserver.scep</c>,
    /// <c>opencertserver.intune</c> and <c>opencertserver.ca</c> meters and activity sources feed a
    /// single metric and a single trace provider, both exported to the endpoint in
    /// <c>Telemetry:OtlpEndpoint</c> (default http://localhost:4317). When disabled nothing is
    /// registered, so the in-process behaviour and the in-process metrics tests are unchanged.
    /// </summary>
    private static IServiceCollection RegisterTelemetry(IServiceCollection services, IConfiguration configuration)
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
                    .AddMeter("opencertserver.acme")
                    .AddMeter("opencertserver.est")
                    .AddMeter("opencertserver.scep")
                    .AddMeter("opencertserver.intune")
                    .AddMeter("opencertserver.ca")
                    .AddMeter("opencertserver.ca.core")
                    .AddMeter("opencertserver.data")
                    .AddMeter("opencertserver.data.postgresql")
                    .AddMeter("opencertserver.data.mssql")
                    .AddOtlpExporter(options => options.Endpoint = endpoint);
            })
            .WithTracing(tracer =>
            {
                tracer
                    .AddSource("opencertserver.acme")
                    .AddSource("opencertserver.est")
                    .AddSource("opencertserver.scep")
                    .AddSource("opencertserver.intune")
                    .AddSource("opencertserver.ca")
                    .AddSource("opencertserver.ca.core")
                    .AddSource("opencertserver.data")
                    .AddSource("opencertserver.data.postgresql")
                    .AddSource("opencertserver.data.mssql")
                    .AddOtlpExporter(options => options.Endpoint = endpoint);
            });

        return services;
    }

    /// <summary>
    /// Reads a configuration section as a list of values: either an array sub-section (<c>0</c>, <c>1</c>,
    /// ...) or a single value whose entries are separated by commas, semicolons or whitespace.
    /// </summary>
    private static List<string> ListConfigValues(IConfigurationSection section)
    {
        var values = section.GetChildren()
            .Select(child => child.Value)
            .OfType<string>()
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToList();
        if (values.Count == 0 && section.Value is { } lone)
        {
            values.AddRange(lone.Split([',', ';', ' ', '\t', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        return values;
    }

    /// <summary>
    /// Wires SCEP like EST and ACME. GetCACaps and GetCACert only publish public information;
    /// PKIOperation issues nothing until a challenge is configured (<c>Scep:Challenge</c>,
    /// e.g. the environment variable <c>Scep__Challenge</c> - not a command line argument,
    /// where it would show in the process list).
    /// </summary>
    private static async Task<IServiceCollection> AddScep(
        IServiceCollection services,
        string[] args,
        IConfiguration configuration)
    {
        // The RA decrypts requests and signs responses; SCEP defines the envelope for RSA
        // key transport only, so the RA is RSA even for an ECDSA CA.
        var raCertificate = GetArgumentValue(args, "--scep-ra") is not null
            ? await CreateCert(args, "--scep-ra", "--scep-ra-key").ConfigureAwait(false)
            : CreateTransientRaCertificate();
        if (raCertificate.GetRSAPrivateKey() is null)
        {
            throw new InvalidOperationException("The SCEP RA certificate (--scep-ra) needs an RSA private key.");
        }

        var options = new ScepServerOptions
        {
            RaCertificate = raCertificate,
            DefaultProfile = configuration["Scep:DefaultProfile"]
        };
        // Intune takes precedence over a shared secret: with <c>Scep:Intune</c> configured,
        // every request is validated by Intune's SCEP validation service, and the revocation
        // sync is mapped (see opencertserver.contrib.intune).
        if (configuration.GetSection(IntuneOptions.SectionName).Exists())
        {
            return services.AddIntune(configuration).AddScepServer(options);
        }

        var challenge = configuration["Scep:Challenge"];
        return string.IsNullOrEmpty(challenge)
            ? services.AddScepServer(options)
            : services.AddScepServer(options, new SharedSecretChallengeValidator(challenge));
    }

    /// <summary>
    /// Without a configured RA, a self-signed one is created at start-up. It changes with
    /// every restart, which SCEP clients tolerate because they fetch GetCACert before each
    /// enrollment; a deployment that pins the RA configures <c>--scep-ra</c>.
    /// </summary>
    private static X509Certificate2 CreateTransientRaCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=OpenCertServer SCEP RA", key, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));
        // Round-trip through PKCS#12 so the key outlives the RSA instance above on every platform.
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pkcs12), null);
    }

    internal static bool ConfigureCertificateForwarding(
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

    private static ForwardedHeadersOptions CreateForwardedHeaderOptions()
    {
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.All,
            ForwardLimit = null,
            AllowedHosts = []
        };
        forwardedHeadersOptions.KnownIPNetworks.Clear();
        forwardedHeadersOptions.KnownProxies.Clear();

        return forwardedHeadersOptions;
    }

    internal static async Task<CaProfile> CreateProfile(
        string[] args,
        IConfiguration configuration,
        string profileName,
        string certArgument,
        string keyArgument,
        string publishedArgument,
        Func<X509Certificate2, AsymmetricAlgorithm?> getPrivateKey)
    {
        using var certificate = await CreateCert(args, certArgument, keyArgument).ConfigureAwait(false);
        var privateKey = getPrivateKey(certificate)
         ?? throw new InvalidOperationException(
                $"The certificate configured for profile '{profileName}' does not expose a compatible private key.");
        using var activeCertificate = X509Certificate2.CreateFromPem(certificate.ExportCertificatePem());
        var publishedCertificatePath =
            GetArgumentValue(args, publishedArgument) ?? configuration[$"{profileName}:PublishedPem"];

        return new CaProfile
        {
            Name = profileName,
            CertificateChain = await LoadCertificateBundle(
                args[Array.IndexOf(args, certArgument) + 1], activeCertificate).ConfigureAwait(false),
            PublishedCertificateChain = await LoadCertificateBundle(publishedCertificatePath, activeCertificate)
                .ConfigureAwait(false),
            CertificateValidity = TimeSpan.FromDays(90),
            CrlNumber = BigInteger.Zero,
            PrivateKey = privateKey,
            CertificatePolicies = ReadList(configuration, $"{profileName}:CertificatePolicies") ?? [],
            KeyUsage = ReadKeyUsage(configuration[$"{profileName}:KeyUsage"]),
            ExtendedKeyUsages = ReadList(configuration, $"{profileName}:ExtendedKeyUsages"),
            TrustAnchors = ReadProfileCaCertificates(configuration, $"{profileName}:TrustAnchors"),
            AdditionalChainCertificates = ReadProfileCaCertificates(
                configuration, $"{profileName}:AdditionalChainCertificates")
        };
    }

    private static X509Certificate2Collection ReadProfileCaCertificates(IConfiguration configuration, string key)
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

    /// <summary>
    /// Reads a list from configuration, either as an array section (<c>rsa:CertificatePolicies:0</c>,
    /// <c>rsa__CertificatePolicies__0</c> in the environment) or as one value with the entries
    /// separated by commas, semicolons or whitespace. Null when the key is absent, so a profile
    /// property that distinguishes "not set" from "empty" keeps that distinction.
    /// </summary>
    private static IReadOnlyList<string>? ReadList(IConfiguration configuration, string key)
    {
        var section = configuration.GetSection(key);
        var children = section.GetChildren().Select(c => c.Value).OfType<string>().ToArray();
        if (children.Length > 0)
        {
            return children;
        }

        return section.Value is { } value
            ? value.Split([',', ';', ' ', '\t', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : null;
    }

    /// <summary>
    /// Reads key usage flags by name, several separated by commas (<c>DigitalSignature, KeyEncipherment</c>).
    /// </summary>
    private static X509KeyUsageFlags? ReadKeyUsage(string? value)
    {
        return string.IsNullOrWhiteSpace(value)
            ? null
            : Enum.Parse<X509KeyUsageFlags>(value, ignoreCase: true);
    }

    private static string? GetArgumentValue(string[] args, string argumentName)
    {
        var index = Array.IndexOf(args, argumentName);
        return index >= 0 && index + 1 < args.Length
            ? args[index + 1]
            : null;
    }

    private static async Task<X509Certificate2Collection> LoadCertificateBundle(
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

    private static void AddUniqueCertificate(
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

    private static async Task<X509Certificate2> CreateCert(string[] args, string cert, string certKey)
    {
        var certIndex = args[Array.IndexOf(args, cert) + 1];
        var keyIndex = Array.IndexOf(args, certKey);
        var key = keyIndex >= 0 ? args[keyIndex + 1] : null;
        using var file = File.OpenText(certIndex);
        using var keyFile = key == null ? TextReader.Null : File.OpenText(key);
        var pem = await file.ReadToEndAsync().ConfigureAwait(false);
        var keyPem = await keyFile.ReadToEndAsync().ConfigureAwait(false);
        var x509 = key == null
            ? X509Certificate2.CreateFromPem(pem)
            : X509Certificate2.CreateFromPem(pem, keyPem);
        return x509;
    }
}
