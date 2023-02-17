namespace OpenCertServer.Est.Cli;

using System.Text;
using Newtonsoft.Json;

internal static partial class Program
{
    private static readonly string ConfigPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "config.json");

    private static async Task<ToolConfig> LoadConfig()
    {
        if (!File.Exists(ConfigPath))
        {
            return new ToolConfig();
        }
        var config = await File.ReadAllTextAsync(ConfigPath, Encoding.UTF8);
        return JsonConvert.DeserializeObject<ToolConfig>(config) ?? new ToolConfig();
    }

    private static async Task Configure(ConfigureArgs configureArgs)
    {
        var config = await LoadConfig();
        config.Server = configureArgs.Server;

        await File.WriteAllTextAsync(ConfigPath, JsonConvert.SerializeObject(config), Encoding.UTF8)
            .ConfigureAwait(false);
    }
}