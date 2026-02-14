namespace OpenCertServer.Est.Cli;

using CommandLine;

[Verb("configure", HelpText = "Configures the EST tool")]
public class ConfigureArgs
{
    [Option('s', "server", Required = true, HelpText = "Sets the URI for the EST server.")]
    public string Server { get; set; } = null!;
}