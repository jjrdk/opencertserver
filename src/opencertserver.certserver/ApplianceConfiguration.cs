namespace OpenCertServer.CertServer;

using System.Security.Authentication;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;

internal sealed class ApplianceOptions
{
    public bool Hardened { get; set; }
    public string Role { get; set; } = "Unified";
    public string? DataDirectory { get; set; }

    public static ApplianceOptions Read(IConfiguration configuration)
    {
        var options = new ApplianceOptions();
        configuration.GetSection("Appliance").Bind(options);
        if (options.Role is not ("Unified" or "Ca" or "Ra"))
        {
            throw new InvalidOperationException("Appliance:Role must be Unified, Ca, or Ra.");
        }

        if (options.Hardened)
        {
            if ((configuration["AllowedHosts"] ?? "").Contains('*'))
            {
                throw new InvalidOperationException("A hardened appliance requires explicit AllowedHosts.");
            }

            if (!string.IsNullOrEmpty(configuration["dn"]))
            {
                throw new InvalidOperationException("A hardened appliance requires persistent CA keys, not dn.");
            }

            if (options.Role != "Ra" && string.IsNullOrWhiteSpace(options.DataDirectory))
            {
                throw new InvalidOperationException(
                    "A hardened CA requires Appliance:DataDirectory on persistent storage.");
            }

            if (options.Role == "Unified" &&
                (configuration.GetValue<bool>("AcmeServer:DisableCaaChecks") ||
                    !configuration.GetValue<bool>("AcmeServer:ExternalAccountRequired") ||
                    !configuration.GetValue<bool>("AcmeServer:HostedWorkers:EnableValidationService") ||
                    !configuration.GetValue<bool>("AcmeServer:HostedWorkers:EnableIssuanceService")))
            {
                throw new InvalidOperationException("A hardened appliance requires CAA, EAB, and both ACME workers.");
            }

            foreach (var endpoint in configuration.GetSection("Kestrel:Endpoints").GetChildren())
            {
                if (!Uri.TryCreate(endpoint["Url"], UriKind.Absolute, out var url) || url.Scheme != "https")
                {
                    throw new InvalidOperationException("A hardened appliance permits only HTTPS listeners.");
                }
            }
        }

        return options;
    }

    public SslProtocols Protocols => Hardened ? SslProtocols.Tls13 : SslProtocols.Tls12 | SslProtocols.Tls13;
}

internal static class ApplianceConfiguration
{
    public const int CurrentVersion = 2;

    public static void AddMountedConfiguration(ConfigurationManager configuration, string[] args)
    {
        var path = configuration["config"] ?? Environment.GetEnvironmentVariable("OPENCERT_CONFIG");
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        var source = ReadDocument(path);
        using var controls = new ConfigurationManager();
        controls.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Migration:AutoApply"] = source["Migration"]?["AutoApply"]?.GetValue<bool>().ToString()
                 ?? configuration["Migration:AutoApply"]
            })
            .AddEnvironmentVariables()
            .AddCommandLine(args);
        var document = MigrationRunner.Upgrade(source, controls.GetValue<bool>("Migration:AutoApply"));
        // A migrated read-only mount is applied in memory; explicit configload writes the upgraded copy.
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(document.ToJsonString()));
        configuration.AddJsonStream(stream);
        configuration.AddEnvironmentVariables().AddCommandLine(args);
    }

    public static bool RunCommand(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("configdump" or "configload"))
        {
            return false;
        }

        if (args.Length != 3)
        {
            throw new ArgumentException("Usage: configdump|configload <source.json> <destination.json>");
        }

        var source = Path.GetFullPath(args[1]);
        var destination = Path.GetFullPath(args[2]);
        if (source == destination || File.Exists(destination))
        {
            throw new IOException("The destination must be a new file; the source is never overwritten.");
        }

        var document = MigrationRunner.Upgrade(ReadDocument(source), autoApply: args[0] == "configload");
        var fileOptions = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None
        };
        if (!OperatingSystem.IsWindows())
        {
            fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        using var output = new FileStream(destination, fileOptions);
        using var writer = new Utf8JsonWriter(output, new JsonWriterOptions { Indented = true });
        document.WriteTo(writer);
        return true;
    }

    internal static JsonObject ReadDocument(string path) =>
        JsonNode.Parse(File.ReadAllText(path)) as JsonObject
     ?? throw new InvalidDataException("Appliance configuration must be a JSON object.");
}

internal static class MigrationRunner
{
    public static JsonObject Upgrade(JsonObject source, bool autoApply)
    {
        var document = (JsonObject)source.DeepClone();
        var version = document["version"]?.GetValue<int>()
         ?? throw new InvalidDataException("A mounted appliance configuration requires an integer version.");
        if (version < 1 || version > ApplianceConfiguration.CurrentVersion)
        {
            throw new InvalidDataException($"Unsupported configuration version {version}.");
        }

        if (version < ApplianceConfiguration.CurrentVersion && !autoApply)
        {
            throw new InvalidOperationException(
                "Configuration upgrade required; use configload or Migration__AutoApply=true.");
        }

        if (version == 1)
        {
            // Version 1 used the command-line JWT names; version 2 groups them under Jwt.
            var jwt = document["Jwt"] as JsonObject ?? new JsonObject();
            if (document.Remove("authority", out var authority))
            {
                jwt["Authority"] ??= authority;
            }

            if (document.Remove("audience", out var audience))
            {
                jwt["Audiences"] ??= new JsonArray(
                    (audience?.GetValue<string>() ?? "").Split(',',
                        StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());
            }

            document["Jwt"] = jwt.DeepClone();
            document["version"] = ApplianceConfiguration.CurrentVersion;
        }

        return document;
    }
}
