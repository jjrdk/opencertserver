namespace OpenCertServer.Est.Cli;

using System.Text.Json;
using System.Text;
using System.Diagnostics.CodeAnalysis;

internal static partial class Program
{
    private static readonly string ConfigPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "config.json");

    [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "Type is part of output signature")]
    [UnconditionalSuppressMessage("AOT", "IL3050:Calling members annotated with 'RequiresDynamicCodeAttribute' may break functionality when AOT compiling.", Justification = "Type is part of output signature")]
    private static async Task<ToolConfig> LoadConfig()
    {
        if (!File.Exists(ConfigPath))
        {
            return new ToolConfig();
        }

        var config = await File.ReadAllTextAsync(ConfigPath, Encoding.UTF8);
        return JsonSerializer.Deserialize<ToolConfig>(config) ?? new ToolConfig();
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code", Justification = "Type is part of input signature")]
    [UnconditionalSuppressMessage("AOT", "IL3050:Calling members annotated with 'RequiresDynamicCodeAttribute' may break functionality when AOT compiling.", Justification = "Type is part of input signature")]
    private static async Task Configure(ConfigureArgs configureArgs)
    {
        var config = await LoadConfig();
        config.Server = configureArgs.Server;

        var json = JsonSerializer.Serialize(config,
            new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true, IncludeFields = false });
        await File.WriteAllTextAsync(ConfigPath, json, Encoding.UTF8)
            .ConfigureAwait(false);

        await Console.Out.WriteLineAsync(json).ConfigureAwait(false);
    }
}
